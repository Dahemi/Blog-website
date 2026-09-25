const cloudinary = require("cloudinary");
const fs = require("fs");
const { randomUUID } = require("crypto");
const keys = require("../config/keys");

// [V8] file-type >=21 (the version that fixes GHSA-5v7r-6r5c-r473) is a pure ESM
// package — it dropped CommonJS support entirely, so it can't be require()'d from
// this file. Loaded via a cached dynamic import instead; every call after the first
// reuses the same resolved function rather than re-importing per upload.
let fileTypeFromFilePromise;
const getFileTypeFromFile = () => {
  if (!fileTypeFromFilePromise) {
    fileTypeFromFilePromise = import("file-type").then((mod) => mod.fileTypeFromFile);
  }
  return fileTypeFromFilePromise;
};

cloudinary.config({
  cloud_name: keys.CLOUD_NAME,
  api_key: keys.CLOUD_API_KEY,
  api_secret: keys.CLOUD_API_SECRET,
});

// V13: allowlist by *detected* content, not by the client-supplied Content-Type.
// SVG is deliberately excluded: it is an XML document that may carry <script>, and
// its magic bytes are indistinguishable from any other XML, so content detection
// cannot separate a safe SVG from a hostile one.
const ALLOWED_MIME = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

// V13 + V8: the Cloudinary `folder` was taken straight from req.body.path. Combined
// with GHSA-g4mf-96x5-5m2c (argument injection via '&' in the Cloudinary Node SDK)
// that is attacker-controlled input reaching the affected parameter.
const ALLOWED_FOLDERS = new Set(["blog", "profile", "post"]);

exports.uploadImages = async (req, res) => {
  const file = req.files && req.files.file;

  if (!file) {
    return res.status(400).json({ message: "No file was uploaded." });
  }

  try {
    // 1. Size — defence in depth; express-fileupload already aborts past the limit
    //    (see backend/app.js), but check again here in case that config ever drifts.
    if (file.size > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ message: "File exceeds the 5 MB limit." });
    }

    // 2. Declared type must be plausible before we spend I/O on it.
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return res.status(415).json({ message: "Only JPEG, PNG and WebP images are accepted." });
    }

    // 3. Magic bytes — the authoritative check. file.mimetype is attacker-chosen
    //    metadata; the first bytes on disk are the actual content. This is what
    //    Evidence 1 in the report proves: a renamed .exe fails right here.
    const fileTypeFromFile = await getFileTypeFromFile();
    const detected = await fileTypeFromFile(file.tempFilePath);
    if (!detected || !ALLOWED_MIME.has(detected.mime)) {
      return res.status(415).json({
        message: "File content is not a supported image.",
        detected: detected ? detected.mime : "unknown",
      });
    }

    // 4. Declared must agree with detected — catches a PNG relabelled as JPEG as
    //    well as an outright renamed executable.
    if (detected.mime !== file.mimetype) {
      return res.status(415).json({
        message: `Content-Type mismatch: declared ${file.mimetype}, detected ${detected.mime}.`,
      });
    }

    // 5. Constrain the Cloudinary folder rather than trusting req.body.path.
    const requested = typeof req.body.path === "string" ? req.body.path : "";
    const folder = ALLOWED_FOLDERS.has(requested) ? requested : "blog";

    // 6. Never reuse the client's filename — generate one.
    const publicId = randomUUID();

    const url = await uploadToCloudinary(file, folder, publicId, detected.ext);
    return res.json([url]);
  } catch (error) {
    return res.status(500).json({ message: "Upload failed." });
  } finally {
    // Always remove the temp file, on every path including rejection — the original
    // only cleaned up on success, so every rejected upload leaked a file.
    removeTmp(file);
  }
};

const uploadToCloudinary = (file, folder, publicId, ext) =>
  new Promise((resolve, reject) => {
    cloudinary.v2.uploader.upload(
      file.tempFilePath,
      {
        folder,
        public_id: publicId,
        resource_type: "image",   // never "auto" — pins Cloudinary to image handling
        allowed_formats: ["jpg", "jpeg", "png", "webp"],
        format: ext,
      },
      // The original called res.status(400) on the *callback's* shadowed `res`, not
      // Express's — so an upload failure threw a TypeError inside the callback with no
      // surrounding try/catch, which crashed the entire Node process (confirmed live,
      // see docs/Aman/pocs/V13/V13-server-crash-stacktrace.txt). Reject properly
      // instead, so the outer try/catch in uploadImages turns it into a clean 500.
      // In practice this branch is now defence in depth: steps 1-4 above already
      // reject non-image content via magic-byte checking before Cloudinary ever sees
      // it, so a renamed executable never reaches this callback post-fix.
      (err, result) => (err ? reject(err) : resolve({ url: result.secure_url }))
    );
  });

const removeTmp = (file) => {
  if (!file || !file.tempFilePath) return;
  // The original did `if (err) throw err` inside this callback — an uncaught
  // exception that terminated the Node process on a failed cleanup.
  fs.unlink(file.tempFilePath, () => {});
};
