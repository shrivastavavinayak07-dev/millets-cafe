
require("dotenv").config({ path: "millets.env" });
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

const ordersFile = path.join(__dirname, "orders.json");

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
    throw new Error(
        "Missing ADMIN_USERNAME, ADMIN_PASSWORD_HASH, or SESSION_SECRET in .env"
    );
}

// Create orders.json if it does not exist.
if (!fs.existsSync(ordersFile)) {
    fs.writeFileSync(ordersFile, "[]", "utf8");
}

// Read orders safely.
function readOrders() {
    const data = JSON.parse(fs.readFileSync(ordersFile, "utf8"));

    if (!Array.isArray(data)) {
        throw new Error("orders.json must contain an array.");
    }

    return data;
}

// Save orders.
function writeOrders(orders) {
    fs.writeFileSync(
        ordersFile,
        JSON.stringify(orders, null, 2),
        "utf8"
    );
}

// Admin authentication middleware.
function requireAdmin(req, res, next) {
    if (req.session?.isAdmin === true) {
        return next();
    }

    return res.status(401).json({
        message: "Please log in as admin."
    });
}

app.disable("x-powered-by");

if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

app.use(
    session({
        name: "millets.sid",
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production",
            maxAge: 30 * 60 * 1000
        }
    })
);

// ===============================
// LOGIN PAGE
// ===============================

app.get("/login-millets.html", (req, res) => {
    if (req.session?.isAdmin) {
        return res.redirect("/admin-millets.html");
    }

    return res.sendFile(
        path.join(__dirname, "login-millets.html")
    );
});

// Admin login API.
app.post("/api/admin/login", async (req, res) => {
    try {
        const { username, password } = req.body || {};

        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "Username and password are required."
            });
        }

        const validUsername = username === ADMIN_USERNAME;
        const validPassword = await bcrypt.compare(
            password,
            ADMIN_PASSWORD_HASH
        );

        if (!validUsername || !validPassword) {
            return res.status(401).json({
                message: "Invalid username or password."
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                return res.status(500).json({
                    message: "Could not start a secure session."
                });
            }

            req.session.isAdmin = true;

            req.session.save((saveError) => {
                if (saveError) {
                    return res.status(500).json({
                        message: "Could not save login session."
                    });
                }

                return res.json({
                    message: "Login successful."
                });
            });
        });
    } catch (error) {
        console.error("Admin login error:", error);

        return res.status(500).json({
            message: "Login failed. Please try again."
        });
    }
});

// Admin logout API.
app.post("/api/admin/logout", (req, res) => {
    req.session.destroy((error) => {
        res.clearCookie("millets.sid", {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production"
        });

        if (error) {
            return res.status(500).json({
                message: "Could not log out."
            });
        }

        return res.json({
            message: "Logged out successfully."
        });
    });
});

// ===============================
// ADMIN DASHBOARD
// ===============================



app.get("/admin-millets.html", requireAdmin, (req, res) => {
    return res.sendFile(
        path.join(__dirname, "adminpage.html")
    );
});


// Fetch all orders. Admin only.
app.get("/api/orders", requireAdmin, (req, res) => {
    try {
        return res.json(readOrders());
    } catch (error) {
        console.error("Read orders error:", error);

        return res.status(500).json({
            message: "Could not load orders."
        });
    }
});

// ===============================
// UPDATE ORDER STATUS
// ===============================

app.patch(
    "/api/orders/:id/status",
    requireAdmin,
    (req, res) => {
        try {
            const { status } = req.body || {};

            const allowedStatuses = [
                "Pending",
                "Confirmed",
                "Cancelled"
            ];

            if (!allowedStatuses.includes(status)) {
                return res.status(400).json({
                    message: "Invalid order status."
                });
            }

            const orders = readOrders();

            const order = orders.find(
                item => String(item.id) === String(req.params.id)
            );

            if (!order) {
                return res.status(404).json({
                    message: "Order not found."
                });
            }

            order.status = status;

            if (status === "Confirmed") {
                order.confirmedAt =
                    order.confirmedAt || new Date().toISOString();
            } else if (status === "Pending") {
                delete order.confirmedAt;
            }

            writeOrders(orders);

            return res.json({
                message: `Order ${status.toLowerCase()} successfully.`,
                order
            });
        } catch (error) {
            console.error("Update status error:", error);

            return res.status(500).json({
                message: "Could not update order status."
            });
        }
    }
);

// ===============================
// DELETE ONE ORDER
// ===============================

app.delete("/api/orders/:id", requireAdmin, (req, res) => {
    try {
        const orders = readOrders();

        const index = orders.findIndex(
            item => String(item.id) === String(req.params.id)
        );

        if (index === -1) {
            return res.status(404).json({
                message: "Order not found."
            });
        }

        orders.splice(index, 1);
        writeOrders(orders);

        return res.json({
            message: "Order deleted successfully."
        });
    } catch (error) {
        console.error("Delete order error:", error);

        return res.status(500).json({
            message: "Could not delete order."
        });
    }
});

// ===============================
// DELETE ALL ORDERS
// ===============================

app.delete("/api/orders", requireAdmin, (req, res) => {
    try {
        const orders = readOrders();
        const deletedCount = orders.length;

        writeOrders([]);

        return res.json({
            message: `${deletedCount} order(s) deleted successfully.`,
            deletedCount
        });
    } catch (error) {
        console.error("Delete all orders error:", error);

        return res.status(500).json({
            message: "Could not delete orders."
        });
    }
});

// ===============================
// CUSTOMER ORDER SUBMISSION
// ===============================

function firstPresent(...values) {
    return values.find(
        value =>
            value !== undefined &&
            value !== null &&
            value !== ""
    );
}

app.post("/api/orders", (req, res) => {
    try {
        const body = req.body || {};

        const fullName = String(
            firstPresent(body.fullName, body.name, "")
        ).trim();

        const phone = String(
            firstPresent(body.phone, body.mobile, "")
        ).trim();

        const items = firstPresent(
            body.items,
            body.orderItems,
            body.cart,
            body.order,
            []
        );

        const totalAmount = firstPresent(
            body.totalAmount,
            body.total,
            body.amount,
            body.grandTotal,
            null
        );

        const paymentMode = firstPresent(
            body.paymentMode,
            body.modeOfPayment,
            body.paymentMethod,
            body.payment,
            "Not specified"
        );

        if (!fullName || !phone) {
            return res.status(400).json({
                message: "Customer name and phone number are required."
            });
        }

        if (fullName.length > 120 || phone.length > 30) {
            return res.status(400).json({
                message: "Name or phone number is too long."
            });
        }

        const safeTotal =
            totalAmount === null ? null : Number(totalAmount);

        if (
            safeTotal !== null &&
            (!Number.isFinite(safeTotal) || safeTotal < 0)
        ) {
            return res.status(400).json({
                message: "Invalid total amount."
            });
        }

        const orders = readOrders();
        const now = new Date();

        // Unique internal ID.
        const id =
            `${now.getTime()}-${crypto.randomBytes(3).toString("hex")}`;

        // Customer-facing order number.
        const orderNumber =
            `MC-${now.toISOString().slice(0, 10).replace(/-/g, "")}-` +
            crypto.randomBytes(3).toString("hex").toUpperCase();

        const newOrder = {
            id,
            orderNumber,

            fullName,
            phone,

            email: String(body.email || "").trim(),

            items,
            totalAmount: safeTotal,
            paymentMode: String(paymentMode).trim().slice(0, 60),

            status: "Pending",

            // Time when the order was placed.
            createdAt: now.toISOString(),

            // Set when admin confirms the order.
            confirmedAt: null
        };

        if (body.notes) {
            newOrder.notes = String(body.notes).trim().slice(0, 1000);
        }

        orders.push(newOrder);
        writeOrders(orders);

        return res.status(201).json({
            message: "Order placed successfully.",
            orderNumber: newOrder.orderNumber,
            orderAt: newOrder.createdAt,
            order: newOrder
        });
    } catch (error) {
        console.error("Save order error:", error);

        return res.status(500).json({
            message: "Could not save order. Please try again."
        });
    }
});

// ===============================
// PROTECT PRIVATE FILES
// ===============================

app.use((req, res, next) => {
    const blockedPaths = new Set([
        "/orders.json",
        "/orders_config.json",
        "/orders-config.json",
        "/millets_server.js",
        "/adminpage.html",
        "/package.json",
        "/package-lock.json",
        "/.env",
        "/millets.env"
    ]);

    if (
        blockedPaths.has(req.path) ||
        req.path.startsWith("/node_modules/") ||
        req.path.endsWith(".env")
    ) {
        return res.sendStatus(404);
    }

    return next();
});

// Serve public website assets only after API routes.
app.use(
    express.static(__dirname, {
        dotfiles: "deny",
        index: false
    })
);

// Homepage.
app.get("/", (req, res) => {
    return res.sendFile(
        path.join(__dirname, "millets.html")
    );
});

app.listen(PORT, () => {
    console.log(`Millets Cafe server running on port ${PORT}`);
});
