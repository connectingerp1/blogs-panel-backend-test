// blogsPanel.js (server file) - Updated for Infinite Scroll and Slugs

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const bcrypt = require("bcryptjs"); // For password hashing
const jwt = require("jsonwebtoken"); // For JWT
const path = require("path"); // This might not be needed if not serving static files directly

const app = express();

// Allowed Origins for CORS
const allowedOrigins = [
  "https://connectingdotserp.com",
  "https://www.connectingdotserp.com",
  "https://blog.connectingdotserp.com", // Your blog frontend domain
  "https://www.blog.connectingdotserp.com",
  "http://localhost:3000", // Your frontend dev server
  "http://localhost:5002", // If your frontend talks to itself on this port during dev
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error("❌ CORS Blocked Origin:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Debugging Middleware
app.use((req, res, next) => {
  console.log("Incoming Request:", req.method, req.url);
  console.log("Origin:", req.headers.origin);
  next();
});

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Blogs MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// --- User Schema & Model for Authentication ---
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      match: [/.+\@.+\..+/, "Please fill a valid email address"],
    },
    password: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

// Hash password before saving the user
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model("User", userSchema);

// ✅ Blog Schema & Model (MODIFIED to add slug)
const blogSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    slug: {
      // NEW FIELD: Slug for friendly URLs
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true, // Index for faster lookup
    },
    content: { type: String, required: true },
    category: { type: String, required: true },
    subcategory: {
      type: String,
      required: true,
      enum: ["Article", "Tutorial", "Interview Questions"],
    },
    author: { type: String, required: true },
    image: { type: String },
    imagePublicId: { type: String },
    status: {
      type: String,
      enum: ["Trending", "Featured", "Editor's Pick", "Recommended", "None"],
      default: "None",
    },
  },
  { timestamps: true }
);

const Blog = mongoose.model("Blog", blogSchema);

// ✅ Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ Helper function to extract public_id from Cloudinary URL (kept as is per original request)
const getPublicIdFromUrl = (url) => {
  if (!url) return null;

  try {
    const urlParts = url.split("/");
    const versionIndex = urlParts.findIndex(
      (part) => part.startsWith("v") && !isNaN(part.substring(1))
    );

    if (versionIndex !== -1 && urlParts.length > versionIndex + 2) {
      const relevantParts = urlParts.slice(versionIndex + 1);
      const publicIdWithExtension = relevantParts.slice(1).join("/");
      return publicIdWithExtension.substring(
        0,
        publicIdWithExtension.lastIndexOf(".")
      );
    } else if (urlParts.length > 1) {
      const fileNameWithExtension = urlParts[urlParts.length - 1];
      const publicIdWithFolder = urlParts
        .slice(urlParts.lastIndexOf("upload") + 2)
        .join("/");
      return publicIdWithFolder.substring(
        0,
        publicIdWithFolder.lastIndexOf(".")
      );
    }
    return null;
  } catch (error) {
    console.error("Error extracting public ID:", error);
    return null;
  }
};

// ✅ Helper function to delete image from Cloudinary
const deleteCloudinaryImage = async (publicId) => {
  if (!publicId) return;

  try {
    console.log(
      `Attempting to delete Cloudinary image with public ID: ${publicId}`
    );
    const result = await cloudinary.uploader.destroy(publicId);
    console.log(`Cloudinary deletion result:`, result);
    return result;
  } catch (error) {
    console.error(`Error deleting Cloudinary image ${publicId}:`, error);
  }
};

// ✅ Multer Storage for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "blog-images",
    format: async (req, file) => "png",
    public_id: (req, file) =>
      Date.now() + "-" + file.originalname.split(".")[0],
  },
});

const upload = multer({ storage });

// --- Helper functions for slug generation (NEW) ---
const generateSlug = (text) => {
  return text
    .toString()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // remove diacritics
    .toLowerCase()
    .trim()
    .replace(/\s+/g, "-") // replace spaces with -
    .replace(/[^\w-]+/g, "") // remove all non-word chars
    .replace(/--+/g, "-"); // replace multiple -- with single -
};

const findUniqueSlug = async (baseSlug, BlogModel, excludeId = null) => {
  let slug = baseSlug;
  let counter = 0;
  while (true) {
    let query = { slug };
    if (excludeId) {
      query._id = { $ne: excludeId }; // Exclude the current blog being updated
    }
    const existingBlog = await BlogModel.findOne(query);
    if (!existingBlog) {
      return slug;
    }
    counter++;
    slug = `${baseSlug}-${counter}`;
  }
};

// --- JWT Authentication Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res
      .status(401)
      .json({ message: "Access Denied: No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT Verification Error:", err);
      return res.status(403).json({ message: "Access Denied: Invalid token" });
    }
    req.user = user;
    next();
  });
};

// --- Authentication Routes ---

// Register User (Optional - for initial setup, can be removed later)
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    let user = await User.findOne({ $or: [{ username }, { email }] });
    if (user) {
      return res
        .status(400)
        .json({ message: "User with that username or email already exists." });
    }

    user = new User({ username, email, password });
    await user.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("Registration Error:", err);
    res
      .status(500)
      .json({ message: "Error registering user", error: err.message });
  }
});

// Login User
app.post("/api/auth/login", async (req, res) => {
  try {
    const { loginIdentifier, password } = req.body;

    const user = await User.findOne({
      $or: [{ username: loginIdentifier }, { email: loginIdentifier }],
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Logged in successfully",
      token,
      username: user.username,
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: "Error during login", error: err.message });
  }
});

// === Wake/Ping Endpoint ===
app.get("/api/blogs/ping", (req, res) => {
  res.status(200).json({ message: "Server is awake!" });
});

// ✅ Fetch all blogs (now supports infinite scroll via limit/skip)
app.get("/api/blogs", async (req, res) => {
  try {
    const { category, subcategory, status, limit, skip } = req.query;
    let query = {};
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (status) query.status = status;

    const parsedLimit = parseInt(limit) || 8; // Default limit of 8 per load
    const parsedSkip = parseInt(skip) || 0; // Default skip of 0

    // Fetch blogs, sort by newest first, and add 1 extra to check for 'hasMore'
    const blogs = await Blog.find(query)
      .sort({ createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit + 1);

    const hasMore = blogs.length > parsedLimit;
    const blogsToSend = hasMore ? blogs.slice(0, parsedLimit) : blogs;

    res.json({ blogs: blogsToSend, hasMore });
  } catch (err) {
    console.error("Error fetching blogs:", err);
    res
      .status(500)
      .json({ message: "Error fetching blogs", error: err.message });
  }
});

// ✅ Fetch blog by SLUG (NEW ROUTE)
app.get("/api/blogs/slug/:slug", async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug }); // Find by slug
    if (!blog) return res.status(404).json({ message: "Blog not found" });

    res.json(blog);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ Fetch blog by ID with proper ObjectId validation (UNCHANGED)
app.get("/api/blogs/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }

    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: "Blog not found" });

    res.json(blog);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ Create a new blog with Cloudinary image upload (MODIFIED to handle slug)
app.post(
  "/api/blogs",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const {
        title,
        content,
        category,
        subcategory,
        author,
        status,
        slug: providedSlug,
      } = req.body; // Destructure providedSlug from req.body

      // Generate slug based on providedSlug or title
      let blogSlug;
      if (providedSlug) {
        blogSlug = generateSlug(providedSlug); // Sanitize the provided slug
      } else {
        blogSlug = generateSlug(title); // Generate from title
      }
      blogSlug = await findUniqueSlug(blogSlug, Blog); // Ensure uniqueness in DB

      let imagePath = null;
      let imagePublicId = null;

      if (req.file) {
        imagePath = req.file.path;
        imagePublicId = req.file.filename || getPublicIdFromUrl(imagePath);
      }

      const newBlog = new Blog({
        title,
        slug: blogSlug, // Assign the generated unique slug
        content,
        category,
        subcategory,
        author,
        image: imagePath,
        imagePublicId,
        status: status || "None",
      });

      await newBlog.save();

      res
        .status(201)
        .json({ message: "Blog created successfully", blog: newBlog });
    } catch (err) {
      // Handle duplicate key error for slug field
      if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
        return res
          .status(409)
          .json({
            message:
              "A blog with a similar title/slug already exists. Please choose a unique title or provide a custom slug.",
            error: err.message,
          });
      }
      console.error("Error creating blog:", err);
      res
        .status(500)
        .json({ message: "Error creating blog", error: err.message });
    }
  }
);

// ✅ Update a blog (Supports optional image update, deletes old image, and handles slug update) (MODIFIED)
app.put(
  "/api/blogs/:id", // Still using :id for identification of the blog to update
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: "Invalid Blog ID format" });
      }

      const existingBlog = await Blog.findById(req.params.id);
      if (!existingBlog)
        return res.status(404).json({ message: "Blog not found" });

      let updatedData = { ...req.body }; // Make a copy of req.body

      // Handle slug generation/update logic
      if (updatedData.title || updatedData.slug) {
        let baseSlug;
        if (updatedData.slug) {
          baseSlug = generateSlug(updatedData.slug); // Use provided slug for base
        } else {
          // If title changed but no slug provided, generate from new title
          baseSlug = generateSlug(updatedData.title || existingBlog.title);
        }

        // Only regenerate/validate if the base slug is different from the current one
        // This prevents trying to find a unique slug for the exact same slug
        if (baseSlug !== existingBlog.slug) {
          const uniqueSlug = await findUniqueSlug(
            baseSlug,
            Blog,
            existingBlog._id
          );
          updatedData.slug = uniqueSlug;
        } else {
          // If the slug is unchanged or derived to be the same, keep the existing one
          updatedData.slug = existingBlog.slug;
        }
      }

      if (req.file) {
        if (existingBlog.imagePublicId) {
          await deleteCloudinaryImage(existingBlog.imagePublicId);
        }
        updatedData.image = req.file.path;
        updatedData.imagePublicId =
          req.file.filename || getPublicIdFromUrl(req.file.path);
      }

      const updatedBlog = await Blog.findByIdAndUpdate(
        req.params.id,
        updatedData,
        { new: true, runValidators: true } // `runValidators: true` ensures slug uniqueness check on update
      );

      res.json({ message: "Blog updated successfully", blog: updatedBlog });
    } catch (err) {
      // Handle duplicate key error for slug field
      if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
        return res
          .status(409)
          .json({
            message:
              "A blog with a similar title/slug already exists. Please choose a unique title or provide a custom slug.",
            error: err.message,
          });
      }
      console.error("Error updating blog:", err);
      res
        .status(500)
        .json({ message: "Error updating blog", error: err.message });
    }
  }
);

// ✅ Delete a blog and its associated image (Protected)
app.delete("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }

    const blogToDelete = await Blog.findById(req.params.id);
    if (!blogToDelete)
      return res.status(404).json({ message: "Blog not found" });

    if (blogToDelete.imagePublicId) {
      await deleteCloudinaryImage(blogToDelete.imagePublicId);
    }

    await Blog.findByIdAndDelete(req.params.id);

    res.json({ message: "Blog and associated image deleted successfully" });
  } catch (err) {
    console.error("Error deleting blog:", err);
    res
      .status(500)
      .json({ message: "Error deleting blog", error: err.message });
  }
});

// ✅ Start the blog server
const PORT = process.env.BLOG_PORT || 5002;
app.listen(PORT, () => console.log(`🚀 Blog server running on port ${PORT}`));
