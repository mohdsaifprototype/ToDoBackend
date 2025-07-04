const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config(); // added to load environment variables in vscode
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
/* const { status } = require("express/lib/response"); */
const app = express();
const PORT = process.env.PORT || 8080;
const MONGO_URL = process.env.MONGO_URL;
app.use(express.json());

app.use(
	cors({
		origin: "*",
	})
);

mongoose.connect(MONGO_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
	userName: String,
	password: String,
});

const User = mongoose.model("User", userSchema);

const taskSchema = new mongoose.Schema({
	text: String,
	status: String,
	priority: String,
	userId: mongoose.Schema.Types.ObjectId,
});

const Task = mongoose.model("Task", taskSchema);

app.post("/register", async (req, res) => {
	const { userName, password } = req.body;
	const hashed = await bcrypt.hash(password, 10);
	const user = new User({
		userName,
		password: hashed,
	});
	await user.save();
	res.json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
	const { userName, password } = req.body;
	const user = await User.findOne({ userName });
	if (!user || !(await bcrypt.compare(password, user.password))) {
		return res.status(401).json({ message: "Invalid credentials" });
	}
	const token = jwt.sign({ userId: user._id }, "secret", { expiresIn: "1h" });
	res.json({ token });
});

// Authentication middleware
const authMiddleware = (req, res, next) => {
	const token = req.headers.authorization?.replace("Bearer ", "");
	if (!token) {
		return res
			.status(401)
			.json({ message: "Unauthorized | No token provided" });
	}
	try {
		const decoded = jwt.verify(token, "secret");
		req.userId = decoded.userId;
		next();
	} catch (error) {
		return res.status(401).json({ message: "Invalid token" });
	}
};
// Get tasks request
app.get("/task", authMiddleware, async (req, res) => {
	const tasks = await Task.find({ userId: req.userId });
	res.json(tasks);
});
// Post task request
app.post("/task", authMiddleware, async (req, res) => {
	const task = new Task({ ...req.body, UserId: req.userId });
	await task.save();
	res.json(task);
});
// delete task request
app.delete("/task/:id", authMiddleware, async (req, res) => {
	await Task.findOneAndDelete({ _id: req.params.id.userId });
	res.json({ message: "Task deleted successfully" });
});
// Update status of task request
app.patch("/tasks/:id/status", authMiddleware, async (req, res) => {
	const { status } = req.body;
	const task = await Task.findOneAndUpdate(
		{ _id: req.params.id, userId: req.userId },
		{ status },
		{ new: true }
	);
	if (!task) return res.status(404).json({ message: "Task not found" });
	res.json(task);
});

app.patch("/tasks/:id/priority", authMiddleware, async (req, res) => {
	const { priority } = req.body;
	const task = await Task.findOneAndUpdate(
		{ _id: req.params.id, userId: req.userId },
		{ priority },
		{ new: true }
	);
	if (!task) return res.status(404).json({ message: "Task not found" });
	res.json(task);
});

app.listen(8080, () => console.log("Server started on port 8080"));
