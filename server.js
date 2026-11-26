const express = require("express");
const cors = require("cors");
const {
  MongoClient,
  ServerApiVersion,
  ObjectId,
} = require("mongodb");
const {
  createRemoteJWKSet,
  jwtVerify,
} = require("jose-cjs");
const multer = require("multer");
const sharp = require("sharp");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

// ==========================================
// CONFIGURATION
// ==========================================

const uri = process.env.MONGODB_URI;
const DB_NAME = process.env.AUTH_DB_NAME || "Friend invest";
 
const APP_URL =
  process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

const IMGBB_API_KEY = process.env.IMGBB_API_KEY;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const JWKS = createRemoteJWKSet(
  new URL(`${APP_URL}/api/auth/jwks`)
);

app.use(
  cors({
    credentials: true,
    origin: [
      APP_URL,
      ...(process.env.EXTRA_FRONTEND_URL
        ? process.env.EXTRA_FRONTEND_URL.split(",").map(url => url.trim())
        : []),
    ],
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// ==========================================
// MONGODB COLLECTIONS
// ==========================================

let db;

let membersCollection;
let depositsCollection;
let usersCollection;
let settingsCollection;
let notificationsCollection;
let countersCollection;

// ==========================================
// MULTER IMAGE UPLOAD
// ==========================================

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: {
    fileSize: 8 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed."));
    }

    cb(null, true);
  },
});

// ==========================================
// HELPER FUNCTIONS
// ==========================================

const logger = (req, res, next) => {
  console.log(req.method, req.originalUrl);
  next();
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

const isValidId = (id) => ObjectId.isValid(id);

const getPagination = (query) => {
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 10));

  return {
    page,
    limit,
    skip: (page - 1) * limit,
  };
};

const escapeRegex = (value) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const validAmount = (value) => {
  const amount = Number(value);

  return Number.isFinite(amount) && amount > 0
    ? amount
    : null;
};

const isAdminRole = (role) =>
  role === "admin" || role === "main_admin";

const findAuthUser = (userId) => {
  const idFilters = [{ id: userId }, { _id: userId }];

  if (ObjectId.isValid(userId)) {
    idFilters.push({ _id: new ObjectId(userId) });
  }

  return usersCollection.findOne({ $or: idFilters });
};

const getMembershipStatus = (user) =>
  user.membershipStatus === "active" ? "active" : "inactive";

async function provisionMemberForUser(user) {
  const authUserId = String(user.id || user._id);
  let member = await membersCollection.findOne({ authUserId });

  if (!member) {
    const newMember = {
      authUserId,
      memberId: await generateMemberId(),
      name: user.name || "",
      email: user.email || "",
      phone: user.phone || "",
      address: "",
      image: "",
      status: getMembershipStatus(user),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    try {
      const result = await membersCollection.insertOne(newMember);
      member = { ...newMember, _id: result.insertedId };
    } catch (error) {
      if (error.code !== 11000) throw error;

      member = await membersCollection.findOne({ authUserId });
      if (!member) throw error;
    }
  }

  if (["active", "inactive"].includes(member.status)) {
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { membershipStatus: member.status } }
    );
  }

  return member;
}

async function provisionUnlinkedAuthUsers() {
  const users = await usersCollection
    .find({ role: { $nin: ["admin", "main_admin"] } })
    .toArray();
  const authUserIds = users.map(user => String(user.id || user._id));

  if (!authUserIds.length) return;

  const linkedMembers = await membersCollection
    .find(
      { authUserId: { $in: authUserIds } },
      { projection: { authUserId: 1 } }
    )
    .toArray();
  const linkedIds = new Set(
    linkedMembers.map(member => member.authUserId)
  );

  for (const user of users) {
    const authUserId = String(user.id || user._id);
    if (!linkedIds.has(authUserId)) {
      await provisionMemberForUser(user);
    }
  }
}

// ==========================================
// BETTER AUTH JWT VERIFICATION
// ==========================================

const verityToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const { payload } = await jwtVerify(token, JWKS);

    if (!payload.sub) {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    req.user = payload;

    next();
  } catch (error) {
    console.error("Token validation failed:", error.message);

    return res.status(401).json({
      success: false,
      message: "Unauthorized",
    });
  }
};

// ==========================================
// ROLE VERIFICATION
// ==========================================

const verifyAdmin = async (req, res, next) => {
  try {
    const user = await findAuthUser(req.user.sub);

    if (!user) {
      return res.status(403).json({
        success: false,
        message: "Admin account could not be matched to the authenticated user.",
      });
    }

    if (!isAdminRole(user.role)) {
      return res.status(403).json({
        success: false,
        message: "Admin role is not enabled for this account.",
      });
    }

    req.authUser = user;

    next();
  } catch (error) {
    next(error);
  }
};

const verifyMember = async (req, res, next) => {
  try {
    const user = await findAuthUser(req.user.sub);

    if (!user || isAdminRole(user.role)) {
      return res.status(403).json({
        success: false,
        message: "Member access required",
      });
    }

    req.member = await provisionMemberForUser(user);

    if (!req.member || req.member.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Your membership is awaiting admin approval.",
      });
    }

    req.authUser = user;

    next();
  } catch (error) {
    next(error);
  }
};

// ==========================================
// MEMBER ID GENERATOR
// ==========================================

async function generateMemberId() {
  let memberId;

  do {
    const result = await countersCollection.findOneAndUpdate(
      { _id: "memberId" },
      { $inc: { value: 1 } },
      {
        upsert: true,
        returnDocument: "after",
        includeResultMetadata: false,
      }
    );

    const counter = result?.value;

    if (!Number.isInteger(counter)) {
      throw new Error("Unable to generate a member ID.");
    }

    memberId = `FB-${String(counter).padStart(3, "0")}`;
  } while (await membersCollection.findOne(
    { memberId },
    { projection: { _id: 1 } }
  ));

  return memberId;
}

// ==========================================
// IMGBB + SHARP IMAGE COMPRESSION
// ==========================================

async function uploadImageToImgBB(file) {
  try {
    if (!IMGBB_API_KEY) {
      throw new Error("IMGBB_API_KEY is missing.");
    }

    // Image compression using Sharp
    const compressedImage = await sharp(file.buffer)
      .rotate()
      .resize({
        width: 1600,
        height: 1600,
        fit: "inside",
        withoutEnlargement: true,
      })
      .jpeg({
        quality: 78,
        mozjpeg: true,
      })
      .toBuffer();

    // Convert compressed image to Base64
    const base64Image = compressedImage.toString("base64");

    // ImgBB upload
    const formData = new URLSearchParams();

    formData.append("image", base64Image);

    const response = await fetch(
      `https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`,
      {
        method: "POST",
        body: formData,
      }
    );

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(
        data.error?.message || "ImgBB upload failed."
      );
    }

    return {
      url: data.data.url,
      displayUrl: data.data.display_url,
      deleteUrl: data.data.delete_url,
      compressedSize: compressedImage.length,
    };
  } catch (error) {
    console.error("Image upload error:", error);
    throw error;
  }
}

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Friend Invest Backend Running",
    database: DB_NAME,
  });
});

// ==========================================
// MEMBER DASHBOARD
// ==========================================

app.get(
  "/dashboard",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    const userId = req.user.sub;

    const [
      totalDeposit,
      pendingDeposits,
      totalMembers,
      settings,
      monthly,
    ] = await Promise.all([
      depositsCollection.aggregate([
        {
          $match: {
            userId,
            status: "verified",
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
          },
        },
      ]).toArray(),

      depositsCollection.countDocuments({
        userId,
        status: "pending",
      }),

      membersCollection.countDocuments({
        status: "active",
      }),

      settingsCollection.findOne({
        _id: "organization",
      }),

      depositsCollection.aggregate([
        {
          $match: {
            userId,
            status: "verified",
          },
        },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
            },
            total: { $sum: "$amount" },
          },
        },
        {
          $sort: {
            "_id.year": 1,
            "_id.month": 1,
          },
        },
      ]).toArray(),
    ]);

    const balance = totalDeposit[0]?.total || 0;
    const target = Number(settings?.targetAmount || 0);

    res.json({
      success: true,
      member: req.member,

      statistics: {
        totalDeposit: balance,
        pendingDeposits,
        totalMembers,
        targetAmount: target,
        progress: target
          ? Math.min((balance / target) * 100, 100)
          : 0,
        remainingAmount: Math.max(target - balance, 0),
      },

      monthly,
    });
  })
);

// ==========================================
// MEMBER PROFILE
// ==========================================

app.get(
  "/members/me",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    const userId = req.user.sub;

    const [total, count] = await Promise.all([
      depositsCollection.aggregate([
        {
          $match: {
            userId,
            status: "verified",
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
          },
        },
      ]).toArray(),

      depositsCollection.countDocuments({
        userId,
        status: "verified",
      }),
    ]);

    res.json({
      success: true,
      member: req.member,
      statistics: {
        totalDeposit: total[0]?.total || 0,
        verifiedDeposits: count,
      },
    });
  })
);

app.patch(
  "/members/me",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    const update = {};

    ["name", "phone", "address", "image"].forEach((key) => {
      if (typeof req.body[key] === "string") {
        update[key] = req.body[key].trim();
      }
    });

    if (
      update.phone &&
      !/^01[0-9]{9}$/.test(update.phone)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid Bangladesh phone number.",
      });
    }

    update.updatedAt = new Date();

    await membersCollection.updateOne(
      { _id: req.member._id },
      { $set: update }
    );

    res.json({
      success: true,
      message: "Profile updated successfully.",
    });
  })
);

app.post(
  "/members/register",
  verityToken,
  asyncHandler(async (req, res) => {
    const user = await findAuthUser(req.user.sub);

    if (!user || isAdminRole(user.role)) {
      return res.status(403).json({
        success: false,
        message: "Member registration is not available for this account.",
      });
    }

    const member = await provisionMemberForUser(user);

    res.status(200).json({
      success: true,
      message: "Member registration submitted for admin approval.",
      member,
    });
  })
);

// ==========================================
// MEMBER DEPOSIT SUBMISSION
// ==========================================

app.post(
  "/deposits",
  verityToken,
  verifyMember,
  upload.single("screenshot"),
  asyncHandler(async (req, res) => {
    const {
      paymentMethod,
      amount,
      phone,
      transactionId,
      depositDate,
    } = req.body;

    const numericAmount = validAmount(amount);

    if (!numericAmount) {
      return res.status(400).json({
        success: false,
        message: "Invalid deposit amount.",
      });
    }

    if (!["bKash", "Nagad", "Rocket"].includes(paymentMethod)) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment method.",
      });
    }

    if (!phone || !transactionId || !req.file) {
      return res.status(400).json({
        success: false,
        message: "Phone, Transaction ID and Screenshot are required.",
      });
    }

    const trxId = String(transactionId).trim().toUpperCase();

    const existing = await depositsCollection.findOne({
      transactionId: trxId,
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Transaction ID already exists.",
      });
    }

    // Compress and upload image to ImgBB
    const screenshot = await uploadImageToImgBB(req.file);

    const deposit = {
      userId: req.user.sub,
      memberId: req.member.memberId,
      memberName: req.member.name,
      memberEmail: req.member.email,

      paymentMethod,
      amount: numericAmount,
      phone: String(phone).trim(),
      transactionId: trxId,

      depositDate:
        depositDate || new Date().toISOString().slice(0, 10),

      screenshot: screenshot.url,
      screenshotDeleteUrl: screenshot.deleteUrl,

      status: "pending",
      rejectionReason: "",

      reviewedBy: null,
      reviewedAt: null,

      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await depositsCollection.insertOne(deposit);

    res.status(201).json({
      success: true,
      message: "Deposit submitted successfully.",
      deposit: {
        ...deposit,
        _id: result.insertedId,
      },
      compressedImageSize: screenshot.compressedSize,
    });
  })
);

// ==========================================
// MEMBER DEPOSIT HISTORY
// ==========================================

app.get(
  "/deposits/mine",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = getPagination(req.query);

    const query = {
      userId: req.user.sub,
    };

    if (
      ["pending", "verified", "rejected"].includes(req.query.status)
    ) {
      query.status = req.query.status;
    }

    const [deposits, total] = await Promise.all([
      depositsCollection
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),

      depositsCollection.countDocuments(query),
    ]);

    res.json({
      success: true,
      deposits,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  })
);

// ==========================================
// MEMBER NOTIFICATIONS
// ==========================================

app.get(
  "/notifications",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    const notifications = await notificationsCollection
      .find({ userId: req.user.sub })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    res.json({
      success: true,
      notifications,
      unreadCount: notifications.filter(item => !item.read).length,
    });
  })
);

app.patch(
  "/notifications/:id/read",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid notification ID.",
      });
    }

    const result = await notificationsCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
        userId: req.user.sub,
      },
      {
        $set: {
          read: true,
          readAt: new Date(),
        },
      }
    );

    if (!result.matchedCount) {
      return res.status(404).json({
        success: false,
        message: "Notification not found.",
      });
    }

    res.json({
      success: true,
      message: "Notification marked as read.",
    });
  })
);

app.patch(
  "/notifications/read-all",
  verityToken,
  verifyMember,
  asyncHandler(async (req, res) => {
    await notificationsCollection.updateMany(
      {
        userId: req.user.sub,
        read: false,
      },
      {
        $set: {
          read: true,
          readAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "All notifications marked as read.",
    });
  })
);

// ==========================================
// ADMIN DASHBOARD
// ==========================================

app.get(
  "/admin/dashboard",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const currentMonth = new Date();

    const monthStart = new Date(
      currentMonth.getFullYear(),
      currentMonth.getMonth(),
      1
    );

    const [
      totalMembers,
      pendingDeposits,
      verifiedDeposits,
      rejectedDeposits,
      totalDeposit,
      monthlyDeposit,
      recentDeposits,
      settings,
      topContributors,
    ] = await Promise.all([
      membersCollection.countDocuments({ status: "active" }),

      depositsCollection.countDocuments({ status: "pending" }),

      depositsCollection.countDocuments({ status: "verified" }),

      depositsCollection.countDocuments({ status: "rejected" }),

      depositsCollection.aggregate([
        { $match: { status: "verified" } },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
          },
        },
      ]).toArray(),

      depositsCollection.aggregate([
        {
          $match: {
            status: "verified",
            createdAt: { $gte: monthStart },
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
          },
        },
      ]).toArray(),

      depositsCollection
        .find({})
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray(),

      settingsCollection.findOne({
        _id: "organization",
      }),

      depositsCollection.aggregate([
        { $match: { status: "verified" } },
        {
          $group: {
            _id: "$userId",
            name: { $first: "$memberName" },
            memberId: { $first: "$memberId" },
            total: { $sum: "$amount" },
          },
        },
        { $sort: { total: -1 } },
        { $limit: 5 },
      ]).toArray(),
    ]);

    const balance = totalDeposit[0]?.total || 0;
    const target = Number(settings?.targetAmount || 0);

    res.json({
      success: true,

      statistics: {
        bankBalance: balance,
        totalMembers,
        pendingDeposits,
        verifiedDeposits,
        rejectedDeposits,
        monthlyDeposit: monthlyDeposit[0]?.total || 0,
        targetAmount: target,
        progress: target
          ? Math.min((balance / target) * 100, 100)
          : 0,
        remainingAmount: Math.max(target - balance, 0),
      },

      recentDeposits,
      topContributors,
    });
  })
);

// ==========================================
// ADMIN DEPOSIT MANAGEMENT
// ==========================================

const getAdminDeposits = async (req, res) => {
  const { page, limit, skip } = getPagination(req.query);

  const query = {};

  if (
    ["pending", "verified", "rejected"].includes(req.query.status)
  ) {
    query.status = req.query.status;
  }

  if (req.query.search?.trim()) {
    const regex = new RegExp(
      escapeRegex(req.query.search.trim()),
      "i"
    );

    query.$or = [
      { memberName: regex },
      { memberId: regex },
      { transactionId: regex },
      { phone: regex },
    ];
  }

  const [deposits, total] = await Promise.all([
    depositsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray(),

    depositsCollection.countDocuments(query),
  ]);

  res.json({
    success: true,
    deposits,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
};

app.get(
  "/deposits",
  verityToken,
  verifyAdmin,
  asyncHandler(getAdminDeposits)
);

app.get(
  "/admin/deposits",
  verityToken,
  verifyAdmin,
  asyncHandler(getAdminDeposits)
);

app.patch(
  "/deposits/:id/review",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const { status, rejectionReason = "", note = "" } = req.body;
    const finalRejectionReason = String(rejectionReason || note).trim();

    if (!isValidId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid deposit ID.",
      });
    }

    if (!["verified", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid deposit status.",
      });
    }

    if (
      status === "rejected" &&
      !finalRejectionReason
    ) {
      return res.status(400).json({
        success: false,
        message: "Rejection reason is required.",
      });
    }

    const deposit = await depositsCollection.findOne({
      _id: new ObjectId(req.params.id),
      status: "pending",
    });

    if (!deposit) {
      return res.status(404).json({
        success: false,
        message: "Pending deposit not found.",
      });
    }

    const result = await depositsCollection.updateOne(
      {
        _id: deposit._id,
        status: "pending",
      },
      {
        $set: {
          status,
          rejectionReason:
            status === "rejected"
            ? finalRejectionReason
              : "",
          reviewedBy: req.user.sub,
          reviewedAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    if (!result.modifiedCount) {
      return res.status(409).json({
        success: false,
        message: "Deposit already reviewed.",
      });
    }

    await notificationsCollection.insertOne({
      userId: deposit.userId,
      title:
        status === "verified"
          ? "Deposit Verified"
          : "Deposit Rejected",
      message:
        status === "verified"
          ? `Your ৳${deposit.amount} deposit has been verified.`
          : `Your deposit was rejected. Reason: ${finalRejectionReason}`,
      type: status === "verified" ? "success" : "warning",
      read: false,
      createdAt: new Date(),
    });

    res.json({
      success: true,
      message:
        status === "verified"
          ? "Deposit verified successfully."
          : "Deposit rejected successfully.",
    });
  })
);

// ==========================================
// ADMIN MEMBER MANAGEMENT
// ==========================================

app.get(
  "/members",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    await provisionUnlinkedAuthUsers();

    const { page, limit, skip } = getPagination(req.query);

    const query = {};

    if (["active", "inactive"].includes(req.query.status)) {
      query.status = req.query.status;
    }

    if (req.query.search?.trim()) {
      const regex = new RegExp(
        escapeRegex(req.query.search.trim()),
        "i"
      );

      query.$or = [
        { name: regex },
        { email: regex },
        { phone: regex },
        { memberId: regex },
      ];
    }

    const [members, total] = await Promise.all([
      membersCollection
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),

      membersCollection.countDocuments(query),
    ]);

    const userIds = members
      .map(member => member.authUserId)
      .filter(Boolean);

    const deposits = userIds.length
      ? await depositsCollection.aggregate([
          {
            $match: {
              userId: { $in: userIds },
              status: "verified",
            },
          },
          {
            $group: {
              _id: "$userId",
              total: { $sum: "$amount" },
            },
          },
        ]).toArray()
      : [];

    const depositMap = Object.fromEntries(
      deposits.map(item => [item._id, item.total])
    );

    res.json({
      success: true,

      members: members.map(member => ({
        ...member,
        totalDeposit: member.authUserId
          ? depositMap[member.authUserId] || 0
          : 0,
      })),

      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  })
);

app.get(
  "/members/:id",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const id = req.params.id;

    const member = await membersCollection.findOne({
      $or: [
        { memberId: id },
        ...(isValidId(id)
          ? [{ _id: new ObjectId(id) }]
          : []),
      ],
    });

    if (!member) {
      return res.status(404).json({
        success: false,
        message: "Member not found.",
      });
    }

    const deposits = member.authUserId
      ? await depositsCollection
          .find({ userId: member.authUserId })
          .sort({ createdAt: -1 })
          .toArray()
      : [];

    const totalDeposit = deposits
      .filter(item => item.status === "verified")
      .reduce((sum, item) => sum + Number(item.amount || 0), 0);

    res.json({
      success: true,
      member,
      deposits,
      totalDeposit,
    });
  })
);

app.post(
  "/admin/members",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const {
      name,
      email = "",
      phone = "",
      address = "",
      image = "",
    } = req.body;

    if (!String(name || "").trim()) {
      return res.status(400).json({
        success: false,
        message: "Member name is required.",
      });
    }

    const member = {
      memberId: await generateMemberId(),
      name: String(name).trim(),
      email: String(email).trim(),
      phone: String(phone).trim(),
      address: String(address).trim(),
      image: String(image).trim(),
      status: "active",
      loginEnabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await membersCollection.insertOne(member);

    res.status(201).json({
      success: true,
      message: "Member created successfully.",
      member: {
        ...member,
        _id: result.insertedId,
      },
    });
  })
);

app.patch(
  "/members/:id/status",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const { status } = req.body;
    const id = req.params.id;

    if (!["active", "inactive"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid member status.",
      });
    }

    const memberFilter = {
      $or: [
        { memberId: id },
        ...(isValidId(id)
          ? [{ _id: new ObjectId(id) }]
          : []),
      ],
    };
    const member = await membersCollection.findOne(memberFilter);
    const result = await membersCollection.updateOne(
      memberFilter,
      {
        $set: {
          status,
          updatedAt: new Date(),
        },
      }
    );

    if (!result.matchedCount) {
      return res.status(404).json({
        success: false,
        message: "Member not found.",
      });
    }

    if (member?.authUserId) {
      const authUser = await findAuthUser(member.authUserId);
      if (authUser) {
        await usersCollection.updateOne(
          { _id: authUser._id },
          { $set: { membershipStatus: status } }
        );
      }
    }

    res.json({
      success: true,
      message: "Member status updated successfully.",
    });
  })
);

// ==========================================
// ADMIN FINANCIAL REPORTS
// ==========================================

app.get(
  "/admin/reports",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const year =
      parseInt(req.query.year) || new Date().getFullYear();

    const month = parseInt(req.query.month);

    const hasMonth = month >= 1 && month <= 12;

    const start = hasMonth
      ? new Date(year, month - 1, 1)
      : new Date(year, 0, 1);

    const end = hasMonth
      ? new Date(year, month, 1)
      : new Date(year + 1, 0, 1);

    const dateMatch = {
      createdAt: {
        $gte: start,
        $lt: end,
      },
    };

    const [
      summary,
      monthly,
      paymentMethods,
      yearlyDeposits,
      settings,
    ] = await Promise.all([
      depositsCollection.aggregate([
        {
          $match: {
            ...dateMatch,
            status: "verified",
          },
        },
        {
          $group: {
            _id: null,
            totalAmount: { $sum: "$amount" },
            totalDeposits: { $sum: 1 },
          },
        },
      ]).toArray(),

      depositsCollection.aggregate([
        {
          $match: {
            status: "verified",
            createdAt: {
              $gte: new Date(year, 0, 1),
              $lt: new Date(year + 1, 0, 1),
            },
          },
        },
        {
          $group: {
            _id: { $month: "$createdAt" },
            total: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ]).toArray(),

      depositsCollection.aggregate([
        {
          $match: {
            ...dateMatch,
            status: "verified",
          },
        },
        {
          $group: {
            _id: "$paymentMethod",
            total: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
      ]).toArray(),

      depositsCollection
        .find({
          status: "verified",
          createdAt: {
            $gte: new Date(year, 0, 1),
            $lt: new Date(year + 1, 0, 1),
          },
        })
        .sort({ createdAt: -1 })
        .limit(100)
        .toArray(),

      settingsCollection.findOne({ _id: "organization" }),
    ]);

    res.json({
      success: true,
      year,
      month: hasMonth ? month : null,

      summary: summary[0] || {
        totalAmount: 0,
        totalDeposits: 0,
      },

      monthly: Array.from({ length: 12 }, (_, index) => {
        const item = monthly.find(
          data => data._id === index + 1
        );

        return {
          month: index + 1,
          total: item?.total || 0,
          count: item?.count || 0,
        };
      }),

      paymentMethods,
      targetAmount: Number(settings?.targetAmount || 0),
      transactions: yearlyDeposits.map(item => ({
        _id: item._id,
        title: item.memberName || item.memberId,
        amount: item.amount,
        date: item.depositDate || item.createdAt,
        method: item.paymentMethod,
      })),
    });
  })
);

// ==========================================
// ADMIN ORGANIZATION SETTINGS
// ==========================================

app.get(
  "/admin/settings",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const settings = await settingsCollection.findOne({
      _id: "organization",
    });

    res.json({
      success: true,

      settings: settings || {
        organizationName: "Friends Dream Builders",
        targetAmount: 0,
        monthlyAmount: 0,
        paymentAccounts: {
          bkash: "",
          nagad: "",
          rocket: "",
        },
        notifications: {},
      },
    });
  })
);

app.patch(
  "/admin/settings",
  verityToken,
  verifyAdmin,
  asyncHandler(async (req, res) => {
    const allowed = [
      "organizationName",
      "targetAmount",
      "monthlyAmount",
      "paymentAccounts",
      "notifications",
    ];

    const update = {};

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        update[key] = req.body[key];
      }
    }

    for (const key of ["targetAmount", "monthlyAmount"]) {
      if (update[key] !== undefined) {
        update[key] = Number(update[key]);

        if (
          !Number.isFinite(update[key]) ||
          update[key] < 0
        ) {
          return res.status(400).json({
            success: false,
            message: `Invalid ${key}.`,
          });
        }
      }
    }

    update.updatedAt = new Date();

    await settingsCollection.updateOne(
      { _id: "organization" },
      {
        $set: update,
        $setOnInsert: {
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    res.json({
      success: true,
      message: "Settings updated successfully.",
    });
  })
);

// ==========================================
// 404 HANDLER
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found.",
  });
});

// ==========================================
// GLOBAL ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
  console.error("Backend Error:", error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      message:
        error.code === "LIMIT_FILE_SIZE"
          ? "Image size maximum 8MB."
          : error.message,
    });
  }

  res.status(error.status || 500).json({
    success: false,
    message: error.message || "Internal server error.",
  });
});

// ==========================================
// DATABASE CONNECTION & SERVER START
// ==========================================

async function run() {
  try {
    if (!uri) {
      throw new Error("MONGODB_URI is missing.");
    }

    if (!IMGBB_API_KEY) {
      throw new Error("IMGBB_API_KEY is missing.");
    }

    await client.connect();

    db = client.db(DB_NAME);

    // Collections
    membersCollection = db.collection("members");
    depositsCollection = db.collection("deposits");
    usersCollection = db.collection("user");
    settingsCollection = db.collection("settings");
    notificationsCollection = db.collection("notifications");
    countersCollection = db.collection("counters");

    // Database indexes
    await Promise.all([
      membersCollection.createIndex(
        { authUserId: 1 },
        { unique: true, sparse: true }
      ),

      membersCollection.createIndex(
        { memberId: 1 },
        { unique: true }
      ),

      depositsCollection.createIndex(
        { transactionId: 1 },
        { unique: true }
      ),

      depositsCollection.createIndex({
        userId: 1,
        createdAt: -1,
      }),

      depositsCollection.createIndex({
        status: 1,
        createdAt: -1,
      }),

      notificationsCollection.createIndex({
        userId: 1,
        createdAt: -1,
      }),
    ]);

    console.log("----------------------------------");
    console.log("Friend Invest Backend Connected");
    console.log("MongoDB:", db.databaseName);
    console.log("ImgBB: Enabled");
    console.log("Sharp Compression: Enabled");
    console.log("----------------------------------");

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
      console.log(`Backend URL: http://localhost:${port}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
}

run();

module.exports = app;