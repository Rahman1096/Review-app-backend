const express = require("express");
const path = require("path");
const upload = require("./coverUpload");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config();
mongoose.set("strictQuery", false);
const app = express();

// Trust reverse proxy headers in hosted environments (e.g., Render, Railway)
app.set("trust proxy", 1);

// Allow all in dev; optionally restrict via FRONTEND_URL in production
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? process.env.FRONTEND_URL || "*"
        : "*",
  })
);
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Derive a public-facing base URL for email links. Avoid localhost for recipients off-machine.
function getPublicBaseUrl(req) {
  const raw = req.headers.origin || `${req.protocol}://${req.get("host")}`;
  const isLocal =
    /^(https?:\/\/)?(localhost|127\.0\.0\.1|\[?::1\]?)(:|$)/i.test(raw);
  return isLocal ? process.env.FRONTEND_URL || raw : raw;
}



mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  avatarUrl: String,
  bio: String,
});
const User = mongoose.model("User", userSchema);

// Register Route with email verification
const crypto = require("crypto");
const { sendVerificationEmail, sendPasswordResetEmail } = require("./email");
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Username or email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const user = new User({
      username,
      email,
      password: hashedPassword,
      isAdmin: username === "admin",
      verificationToken,
    });
    await user.save();
    const baseUrl = getPublicBaseUrl(req);
    await sendVerificationEmail(email, verificationToken, username, baseUrl);
    res.json({ message: "User registered. Please verify your email." });
  } catch (err) {
    console.error("Registration error:", err);
    res
      .status(500)
      .json({ message: "Registration failed", error: err.message });
  }
});

// Email verification route
app.get("/api/verify-email", async (req, res) => {
  const { token } = req.query;
  const user = await User.findOne({ verificationToken: token });
  if (!user) return res.status(400).json({ message: "Invalid token" });
  user.isVerified = true;
  user.verificationToken = undefined;
  await user.save();
  res.json({ message: "Email verified!" });
});

// Password reset request
app.post("/api/request-reset", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user)
    return res.status(400).json({ message: "No user with that email" });
  const resetToken = crypto.randomBytes(32).toString("hex");
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 1000 * 60 * 30; // 30 min
  await user.save();
  const baseUrl = getPublicBaseUrl(req);
  await sendPasswordResetEmail(email, resetToken, user.username, baseUrl);
  res.json({ message: "Password reset email sent" });
});

// Password reset
app.post("/api/reset-password", async (req, res) => {
  const { token, password } = req.body;
  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiry: { $gt: Date.now() },
  });
  if (!user)
    return res.status(400).json({ message: "Invalid or expired token" });
  user.password = await bcrypt.hash(password, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();
  res.json({ message: "Password reset successful" });
});

// Login Route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: "Invalid credentials" });
  }
  if (!user.isVerified) {
    return res
      .status(400)
      .json({ message: "Please verify your email before logging in" });
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid credentials" });
  }
  const token = jwt.sign(
    { userId: user._id },
    process.env.JWT_SECRET || "secretkey",
    { expiresIn: "1h" }
  );
  res.json({ token });
});

const reviewSchema = new mongoose.Schema({
  bookTitle: String,
  author: String,
  review: String,
  rating: Number,
  favorite: { type: Boolean, default: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  coverImage: String,
});

// Upload book cover image
app.post("/api/upload-cover", upload.single("cover"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Upload avatar image
app.post("/api/upload-avatar", upload.single("avatar"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });
  res.json({ url: `/uploads/${req.file.filename}` });
});

const Review = mongoose.model("Review", reviewSchema);

app.get("/api/reviews", async (req, res) => {
  const reviews = await Review.find();
  res.json(reviews);
});

// Get current user (profile)
app.get("/api/me", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    const { password, __v, ...safe } = user.toObject();
    res.json(safe);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Update current user (profile)
app.put("/api/me", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    const { username, avatarUrl, bio } = req.body || {};
    if (username && username !== user.username) {
      const exists = await User.findOne({ username });
      if (exists && exists._id.toString() !== user._id.toString()) {
        return res.status(400).json({ message: "Username already taken" });
      }
      user.username = username;
    }
    if (typeof avatarUrl === "string") user.avatarUrl = avatarUrl;
    if (typeof bio === "string") user.bio = bio;
    await user.save();
    const { password, __v, ...safe } = user.toObject();
    res.json(safe);
  } catch (err) {
    res
      .status(400)
      .json({ message: "Failed to update profile", error: err.message });
  }
});

// Change current user's password
app.put("/api/me/password", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Current and new password are required" });
    }
    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok)
      return res.status(400).json({ message: "Current password is incorrect" });
    if (typeof newPassword !== "string" || newPassword.length < 8) {
      return res
        .status(400)
        .json({ message: "New password must be at least 8 characters" });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Failed to update password", error: err.message });
  }
});

// Get reviews by user
app.get("/api/user-reviews", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const reviews = await Review.find({ user: decoded.userId });
    res.json(reviews);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Admin: get all users
app.get("/api/users", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const user = await User.findById(decoded.userId);
    if (!user?.isAdmin) return res.status(403).json({ message: "Forbidden" });
    const users = await User.find();
    res.json(users);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Admin: delete any review
app.delete("/api/admin/reviews/:id", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const user = await User.findById(decoded.userId);
    if (!user?.isAdmin) return res.status(403).json({ message: "Forbidden" });
    await Review.findByIdAndDelete(req.params.id);
    res.json({ message: "Review deleted by admin" });
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

app.post("/api/reviews", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const review = new Review({ ...req.body, user: decoded.userId });
    await review.save();
    res.json(review);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Update review (including favorite status)
app.put("/api/reviews/:id", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ message: "Review not found" });
    const user = await User.findById(decoded.userId);
    const isOwner = review.user?.toString() === decoded.userId;
    if (!isOwner && !user?.isAdmin)
      return res.status(403).json({ message: "Forbidden" });
    Object.assign(review, req.body);
    await review.save();
    res.json(review);
  } catch (err) {
    res.status(400).json({ message: "Failed to update review" });
  }
});

// Toggle favorite status
app.patch("/api/reviews/:id/favorite", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const review = await Review.findById(req.params.id);
    if (!review) {
      console.error("Favorite error: Review not found", req.params.id);
      return res.status(404).json({ message: "Review not found" });
    }
    review.favorite = !review.favorite;
    await review.save();
    res.json(review);
  } catch (err) {
    console.error("Favorite error:", err);
    res.status(401).json({ message: "Unauthorized" });
  }
});

app.delete("/api/reviews/:id", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ message: "Review not found" });
    const user = await User.findById(decoded.userId);
    const isOwner = review.user?.toString() === decoded.userId;
    if (!isOwner && !user?.isAdmin)
      return res.status(403).json({ message: "Forbidden" });
    await Review.findByIdAndDelete(req.params.id);
    res.json({ message: "Review deleted" });
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

const PORT = process.env.PORT || 5000;

// Simple health check
app.get("/health", (req, res) => res.json({ status: "ok" }));

// In production, serve the React build from the client folder
if (process.env.NODE_ENV === "production") {
  const clientBuild = path.join(__dirname, "../client/build");
  app.use(express.static(clientBuild));
  // SPA fallback
  app.get("*", (req, res) => {
    res.sendFile(path.join(clientBuild, "index.html"));
  });
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
