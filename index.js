const dns = require("node:dns");
dns.setServers(["1.1.1.1", "1.0.0.1"]);

const express = require("express");
const dontenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");
dontenv.config();

const uri = process.env.MONGODB_URI;
const app = express();
const PORT = process.env.PORT;

app.use(
  cors({
    credentials: true,
    origin: [process.env.CLIENT_URL],
  }),
);
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`),
);

let userCollection;

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ msg: "Unauthorized" }); // return যোগ করা হলো
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).send({ msg: "Unauthorized" }); // return যোগ করা হলো
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).send({ msg: "Unauthorized" }); // return যোগ করা হলো
  }
};

const verifyAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ msg: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).send({ msg: "Unauthorized" });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);

    if (payload.role !== "admin") {
      return res.status(403).send({ msg: "Forbidden: Admins only" });
    }

    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).send({ msg: "Unauthorized" });
  }
};


async function run() {
  try {
    await client.connect();

    const db = client.db("recipe");
    userCollection = client.db("recipe").collection("user");
    const recipeCollection = db.collection("all_recipe");
    const paymentCollection = db.collection("payment");
    const reportCollection = client.db("recipe").collection("report");
    const FREE_LIMIT = 2;

    app.get("/admin/overview", verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await userCollection.countDocuments();
        const totalRecipes = await recipeCollection.countDocuments();
        const totalPremiumMembers = await userCollection.countDocuments({
          plan: "premium",
        });
        const totalReports = await reportCollection.countDocuments();

        res.send({
          totalUsers,
          totalRecipes,
          totalPremiumMembers,
          totalReports,
        });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // index.js — run() এর ভেতরে যোগ করো
    app.get("/admin/users", verifyAdmin, async (req, res) => {
      try {
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const search = req.query.search || "";

        const query = search
          ? {
              $or: [
                { name: { $regex: search, $options: "i" } },
                { email: { $regex: search, $options: "i" } },
              ],
            }
          : {};

        const total_data = await userCollection.countDocuments(query);
        const total_page = Math.ceil(total_data / limit);

        const users = await userCollection
          .find(query)
          .project({
            name: 1,
            email: 1,
            role: 1,
            plan: 1,
            blocked: 1,
            image: 1,
            createdAt: 1,
          })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({ data: users, total_page, page, total_data });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.patch("/admin/users/:id/block", verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { blocked: true } },
        );

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.patch("/admin/users/:id/unblock", verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { blocked: false } },
        );

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    const optionalVerifyToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        req.user = null;
        return next();
      }
      const token = authHeader.split(" ")[1];
      try {
        const { payload } = await jwtVerify(token, JWKS);
        req.user = payload;
      } catch (error) {
        req.user = null;
      }
      next();
    };

    // index.js — run() এর ভেতরে যোগ করো

    // সব রেসিপি (টেবিল আকারে, paginated)
    app.get("/admin/recipes", verifyAdmin, async (req, res) => {
      try {
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const search = req.query.search || "";

        const query = search
          ? { recipeName: { $regex: search, $options: "i" } }
          : {};

        const total_data = await recipeCollection.countDocuments(query);
        const total_page = Math.ceil(total_data / limit);

        const recipes = await recipeCollection
          .find(query)
          .sort({ _id: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({ data: recipes, total_page, page, total_data });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // Admin দিয়ে যেকোনো রেসিপি ডিলিট
    app.delete("/admin/recipes/:id", verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        await recipeCollection.deleteOne({ _id: new ObjectId(id) });
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

  
    app.patch("/admin/recipes/:id", verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;

        delete updateData._id;
        delete updateData.userId;
        delete updateData.userName;
        delete updateData.userEmail;
        delete updateData.like;
        delete updateData.likedBy;

        await recipeCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

   
    app.patch("/admin/recipes/:id/feature", verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;

        const recipe = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!recipe) {
          return res
            .status(404)
            .send({ success: false, error: "Recipe not found" });
        }

        const nextFeatured = !recipe.featured;

        await recipeCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { featured: nextFeatured } },
        );

        res.send({ success: true, featured: nextFeatured });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.post("/add-recipe", verifyToken, async (req, res) => {
      try {
        const recipe = req.body;
        const user = req.user;

        const recipeCount = await recipeCollection.countDocuments({
          userId: user.id,
        });
        const userDoc = await userCollection.findOne({
          _id: new ObjectId(user.id),
        });
        const plan = userDoc?.plan || "free";

        if (plan !== "premium" && recipeCount >= FREE_LIMIT) {
          return res.status(403).send({
            success: false,
            limitReached: true,
            error:
              "Free plan এ সর্বোচ্চ ২টি রেসিপি যোগ করা যায়। আরও যোগ করতে Premium এ আপগ্রেড করো।",
          });
        }

        const result = await recipeCollection.insertOne(recipe);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

   
    app.post("/recipes/:id/report", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const user = req.user;
        const { reason, details } = req.body;

        const validReasons = ["Spam", "Offensive Content", "Copyright Issue"];
        if (!validReasons.includes(reason)) {
          return res
            .status(400)
            .send({ success: false, error: "Invalid reason" });
        }

        const recipe = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!recipe) {
          return res
            .status(404)
            .send({ success: false, error: "Recipe not found" });
        }

        const alreadyReported = await reportCollection.findOne({
          recipeId: id,
          reportedBy: user.id,
        });

        if (alreadyReported) {
          return res.status(400).send({
            success: false,
            error: "তুমি এই রেসিপি আগেই রিপোর্ট করেছ",
          });
        }

        await reportCollection.insertOne({
          recipeId: id,
          recipeName: recipe.recipeName,
          reason,
          details: details || "",
          reportedBy: user.id,
          reportedByName: user.name || user.email,
          status: "pending",
          createdAt: new Date(),
        });

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // Admin — সব রিপোর্ট লিস্ট (paginated)
    app.get("/admin/reports", verifyAdmin, async (req, res) => {
      try {
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const total_data = await reportCollection.countDocuments();
        const total_page = Math.ceil(total_data / limit);

        const data = await reportCollection
          .find()
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({ data, total_page, page, total_data });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // Admin — রিপোর্ট resolve/dismiss করা
    app.patch("/admin/reports/:id", verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body; // "resolved" বা "dismissed"

        await reportCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } },
        );

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/customer/recipe-status", verifyToken, async (req, res) => {
      try {
        const user = req.user;
        const recipeCount = await recipeCollection.countDocuments({
          userId: user.id,
        });

        const userDoc = await userCollection.findOne({
          _id: new ObjectId(user.id),
        });
        const plan = userDoc?.plan || "free";

        res.send({
          recipeCount,
          plan,
          limit: FREE_LIMIT,
          limitReached: plan !== "premium" && recipeCount >= FREE_LIMIT,
        });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // প্রিমিয়াম আপগ্রেড কনফার্ম করা (Stripe payment সাকসেসের পর কল হবে)
    app.post("/customer/upgrade-premium", verifyToken, async (req, res) => {
      try {
        const user = req.user;
        await userCollection.updateOne(
          { _id: new ObjectId(user.id) },
          { $set: { plan: "premium" } },
        );
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/recipes", async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 8;
        const skip = (page - 1) * limit;
        const search = req.query.search || "";
        const category = req.query.category
          ? req.query.category.split(",")
          : [];
        const cuisineType = req.query.cuisineType
          ? req.query.cuisineType.split(",")
          : [];
        const minTime = req.query.minTime ? Number(req.query.minTime) : null;
        const maxTime = req.query.maxTime ? Number(req.query.maxTime) : null;

        const andConditions = [];

        if (search) {
          andConditions.push({
            $or: [
              { recipeName: { $regex: search, $options: "i" } },
              { category: { $regex: search, $options: "i" } },
              { cuisineType: { $regex: search, $options: "i" } },
            ],
          });
        }

        if (category.length > 0) {
          andConditions.push({ category: { $in: category } });
        }

        if (cuisineType.length > 0) {
          andConditions.push({ cuisineType: { $in: cuisineType } });
        }

        if (minTime !== null || maxTime !== null) {
          const timeQuery = {};
          if (minTime !== null) timeQuery.$gte = minTime;
          if (maxTime !== null) timeQuery.$lte = maxTime;
          andConditions.push({ preparationTime: timeQuery });
        }

        const query = andConditions.length > 0 ? { $and: andConditions } : {};

        const totalCount = await recipeCollection.countDocuments(query);
        const recipes = await recipeCollection
          .find(query)
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          recipes,
          totalCount,
          totalPages: Math.ceil(totalCount / limit),
          currentPage: page,
        });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/recipes/:id", optionalVerifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const recipe = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!recipe) {
          return res.status(404).send({ error: "Recipe not found" });
        }

        let isLiked = false;
        let isFavourited = false;

        if (req.user) {
          isLiked = (recipe.likedBy || []).some(
            (l) => l.userId === req.user.id,
          );

          const userDoc = await userCollection.findOne({
            _id: new ObjectId(req.user.id),
          });
          isFavourited = (userDoc?.favouriteRecipeIds || []).includes(id);
        }

        res.send({ ...recipe, isLiked, isFavourited });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.post("/recipes/:id/favourite", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const user = req.user;

        const userDoc = await userCollection.findOne({
          _id: new ObjectId(user.id),
        });

        if (!userDoc) {
          return res.status(404).send({ error: "User not found in DB" });
        }

        const isFavourited = (userDoc?.favouriteRecipeIds || []).includes(id);

        if (isFavourited) {
          await userCollection.updateOne(
            { _id: new ObjectId(user.id) },
            { $pull: { favouriteRecipeIds: id } },
          );
          return res.send({ favourited: false });
        } else {
          await userCollection.updateOne(
            { _id: new ObjectId(user.id) },
            { $addToSet: { favouriteRecipeIds: id } },
          );
          return res.send({ favourited: true });
        }
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/recipes/featured/list", async (req, res) => {
      try {
        const featuredRecipes = await recipeCollection
          .find({ featured: true })
          .sort({ _id: -1 })
          .limit(8)
          .toArray();

        res.send(featuredRecipes);
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/recipes/popular/list", async (req, res) => {
      try {
        const popularRecipes = await recipeCollection
          .find()
          .sort({ like: -1 })
          .limit(8)
          .toArray();

        res.send(popularRecipes);
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.patch("/recipes/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const user = req.user;
        const updateData = req.body;

        const recipe = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!recipe) {
          return res
            .status(404)
            .send({ success: false, error: "Recipe not found" });
        }

        if (recipe.userId !== user.id) {
          return res.status(403).send({
            success: false,
            error: "You can only update your own recipes",
          });
        }

        // এই ফিল্ডগুলো ইউজার আপডেট করতে পারবে না
        delete updateData._id;
        delete updateData.userId;
        delete updateData.userName;
        delete updateData.userEmail;
        delete updateData.like;
        delete updateData.likedBy;

        await recipeCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });
    app.delete("/recipes/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const user = req.user;

        const recipe = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!recipe) {
          return res
            .status(404)
            .send({ success: false, error: "Recipe not found" });
        }

        if (recipe.userId !== user.id) {
          return res.status(403).send({
            success: false,
            error: "You can only delete your own recipes",
          });
        }

        await recipeCollection.deleteOne({ _id: new ObjectId(id) });

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.post("/recipes/:id/like", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const user = req.user;

        const recipe = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!recipe) {
          return res.status(404).send({ error: "Recipe not found" });
        }

        const alreadyLiked = (recipe.likedBy || []).some(
          (l) => l.userId === user.id,
        );

        if (alreadyLiked) {
          await recipeCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $pull: { likedBy: { userId: user.id } },
              $inc: { like: -1 },
            },
          );
          return res.send({ liked: false });
        } else {
          await recipeCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $push: {
                likedBy: { userId: user.id, userName: user.name || user.email },
              },
              $inc: { like: 1 },
            },
          );
          return res.send({ liked: true });
        }
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // GET /customer/my-favourites এ
    app.get("/customer/my-favourites", verifyToken, async (req, res) => {
      try {
        const user = req.user;
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 8;
        const skip = (page - 1) * limit;

        const userDoc = await userCollection.findOne({
          _id: new ObjectId(user.id), // ফিক্স
        });
        const favIds = userDoc?.favouriteRecipeIds || [];

        const objectIds = favIds.map((fid) => new ObjectId(fid));

        const total_data = objectIds.length;
        const total_page = Math.ceil(total_data / limit);

        const data = await recipeCollection
          .find({ _id: { $in: objectIds } })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({ data, total_page, page, total_data });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/customer/my-recipes", verifyToken, async (req, res) => {
      const limit = Number(req.query.limit) || 10;
      const page = Number(req.query.page) || 1;
      const user = req.user;

      const total_data = await recipeCollection.countDocuments({
        userId: user.id,
      });
      const total_page = Math.ceil(total_data / limit);

      const skip = (page - 1) * limit;

      const data = await recipeCollection
        .find({ userId: user.id })
        .skip(skip)
        .limit(limit)
        .toArray();
      res.send({ total_page, skip, page, data });
    });

    // index.js — run() এর ভেতরে যোগ করো
    app.get("/customer/my-purchased", verifyToken, async (req, res) => {
      try {
        const user = req.user;
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 8;
        const skip = (page - 1) * limit;

        const total_data = await paymentCollection.countDocuments({
          userId: user.id,
        });
        const total_page = Math.ceil(total_data / limit);

        const purchases = await paymentCollection
          .find({ userId: user.id })
          .sort({ _id: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        const recipeIds = purchases
          .filter((p) => p.recipeId)
          .map((p) => new ObjectId(p.recipeId));

        const recipes = await recipeCollection
          .find({ _id: { $in: recipeIds } })
          .toArray();

        const data = purchases.map((purchase) => {
          const recipe = recipes.find(
            (r) => r._id.toString() === purchase.recipeId,
          );
          return {
            ...purchase,
            recipeImage: recipe?.recipeImage || null,
            category: recipe?.category || null,
            cuisineType: recipe?.cuisineType || null,
          };
        });

        res.send({ data, total_page, page, total_data });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/customer/my-recipes-overview", verifyToken, async (req, res) => {
      try {
        const user = req.user;

        const myRecipes = await recipeCollection
          .find({ userId: user.id })
          .project({
            recipeName: 1,
            recipeImage: 1,
            like: 1,
            likedBy: 1,
          })
          .toArray();

        const totalLikes = myRecipes.reduce((sum, r) => sum + (r.like || 0), 0);

        res.send({
          totalRecipes: myRecipes.length,
          totalLikes,
          recipes: myRecipes,
        });
      } catch (error) {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.post("/payment", async (req, res) => {
      const { preparationTime, userId, recipeName, recipeId, session_id } =
        req.body;

      const isExistSession = await paymentCollection.findOne({ session_id });
      if (isExistSession) {
        return res.status(400).send({ message: "Session already exist" });
      }

      const pay_result = await paymentCollection.insertOne({
        userId,
        session_id,
        preparationTime: Number(preparationTime),
        recipeName,
        recipeId,
      });

      res.send({ pay_result });
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Server is running fine!");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
