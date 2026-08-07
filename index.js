const dns = require("node:dns");
// dns.setServers(["1.1.1.1", "1.0.0.1"]);

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

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).send({ msg: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
   return res.status(401).send({ msg: "Unauthorized" });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);
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
    const userCollection = client.db("recipe").collection("user");
    const recipeCollection = db.collection("all_recipe");
    const paymentCollection = db.collection("payment");
    const FREE_LIMIT = 2;

    // /add-recipe রুট প্রতিস্থাপন করো — verifyToken + limit check যোগ
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

    // backend /recipes route (search + filters + pagination)
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

    app.get("/recipes/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const result = await recipeCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(result);
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
