const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

dotenv.config();

const app = express();
const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:5174"],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

const port = process.env.PORT || 5000;

// mongodb
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@smdeveloper.7rzkdcv.mongodb.net/?retryWrites=true&w=majority&appName=SMDeveloper`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db(process.env.DB_NAME);
    const userCollection = db.collection("users");
    console.log("You successfully connected to MongoDB!");

    // jwt related api
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // middleware
    const verifyToken = (req, res, next) => {
      // console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "unauthorized access" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // use verify admin after verifyToken
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    app.put("/register", async (req, res) => {
      const user = req.body;
      const filter = { mobileNumber: user?.mobileNumber };

      //if user already exists
      const exists = await userCollection.findOne(filter);
      if (exists) {
        return res.send({
          acknowledged: false,
          message: "User already exists",
        });
      }

      const options = { upsert: true };

      //Hash the password
      const hassedPassword = await bcrypt.hash(String(user.pin), 10);

      // Store user in the database

      const updateDoc = {
        $set: {
          name: user?.name,
          email: user?.email,
          mobileNumber: user?.mobileNumber,
          pin: hassedPassword,
          lastLogin: user?.lastLogin,
        },
        $setOnInsert: {
          role: user?.role,
          status: user?.status,
          balance: user?.balance,
          createdAt: user?.createdAt,
        },
      };
      const result = await userCollection.updateOne(filter, updateDoc, options);

      res.send(result);
    });

    app.post("/login", async (req, res) => {
      const user = req.body;

      //validation
      if (!user) {
        return res.status(400).json({ message: "Input is required" });
      }

      const isEmail = () => {
        const emailPattern = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
        return emailPattern.test(user?.phoneOrEmail);
      };

      const isPhoneNumber = () => {
        const phonePattern = /^[0-9]{11}$/;
        return phonePattern.test(user?.phoneOrEmail);
      };

      let query;
      if (isEmail()) {
        query = { email: user?.phoneOrEmail };
      } else if (isPhoneNumber()) {
        query = { mobileNumber: Number(user?.phoneOrEmail) };
      } else {
        return res.status(400).json({ message: "Input is invalid" });
      }
      console.log(query);

      const result = await userCollection.findOne(query);

      if (!result) {
        return res.status(404).json({ message: "User not found" });
      }

      const isPasswordValid = await bcrypt.compare(
        String(user?.pin),
        result?.pin
      );

      if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      delete result?.pin;

      res.status(200).send(result);
    });

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const size = parseInt(req.query.size);
      const page = parseInt(req.query.page) - 1;
      const search = req.query.search;
      let query = {
        $or: [
          { name: { $regex: search, $options: "i" } },
          { status: { $regex: search, $options: "i" } },
        ],
      };

      const result = await userCollection
        .find(query)
        .skip(page * size)
        .limit(size)
        .toArray();
      const count = await userCollection.countDocuments(query);
      res.send({ result, count });
    });

    app.patch(
      "/users/admin/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        const user = req.body;

        const filter = { email: email };
        const updateDoc = {
          $set: {
            status: user?.status,
          },
        };
        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      }
    );

    console.log("You successfully connected to MongoDB!");
  } finally {
  }
}
run().catch(console.log);

app.get("/", (req, res) => {
  res.send("Hello from mfs Server..");
});

app.listen(port, () => {
  console.log(`Server is running on Local: http://localhost:${port}`);
});
