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
    const transactionCollection = db.collection("transactions");
    const cashManageCollection = db.collection("cashmanage");
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

    // use verify user after verifyToken
    const verifyUser = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isUser = user?.role === "user";
      if (!isUser) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    // use verify agent after verifyToken
    const verifyAgent = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAgent = user?.role === "agent";
      if (!isAgent) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };
    // User register api
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
    // User login api
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
    // get all users api for admin
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

    // get single user api
    app.get("/user/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await userCollection.findOne(query);
      res.send(result);
    });
    // get single user role and bonus amount update api for admin
    app.patch(
      "/users/admin/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        const user = req.body;
        const filter = { email: email };

        const userInfo = await userCollection.findOne(filter);

        let bonusAmount;

        if (userInfo?.role === "user") {
          bonusAmount = 40;
        } else if (userInfo?.role === "agent") {
          bonusAmount = 10000;
        }

        const newBalance = userInfo?.balance + bonusAmount;

        const isBonusExits = await userCollection.findOne(filter, {
          projection: { getBonusAmount: 1, isGetBonusAmount: 1 },
        });

        let updateDoc;

        if (isBonusExits.isGetBonusAmount) {
          updateDoc = {
            $set: {
              status: user?.status,
            },
          };
        } else if (user?.status === "block") {
          updateDoc = {
            $set: {
              status: user?.status,
            },
          };
        } else {
          updateDoc = {
            $set: {
              status: user?.status,
              getBonusAmount: bonusAmount,
              isGetBonusAmount: true,
              balance: newBalance,
            },
          };
        }
        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      }
    );

    // Send money api for user and agent
    app.post("/user/send-money", verifyToken, verifyUser, async (req, res) => {
      const userInfo = req.body;
      const userFilter = { email: userInfo?.userEmail };
      const recipientFilter = { mobileNumber: userInfo?.recipient };

      try {
        // check is user exisit or not
        const user = await userCollection.findOne(userFilter);
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // check is recipient exisit or not
        const recipient = await userCollection.findOne(recipientFilter);
        if (!recipient) {
          return res.status(404).json({ message: "Recipient not found" });
        }

        // check recipient role is user or not
        if (recipient?.role !== "user") {
          return res.status(400).json({ message: "Recipient is not a user" });
        }

        // if user pin is not matched

        const isPasswordValid = await bcrypt.compare(
          String(userInfo?.pin),
          user?.pin
        );

        if (!isPasswordValid) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        // if amount is more than 100 and insufficient balance

        let fee = 0;
        if (userInfo?.amount > 100) {
          fee = 5;
        }

        if (user.balance < userInfo?.amount + fee) {
          return res.status(400).json({ message: "Insufficient balance" });
        }

        // send money to recipient and update balance
        const updateDoc = {
          $set: {
            balance: user.balance - userInfo?.amount - fee,
          },
        };

        const result = await userCollection.updateOne(userFilter, updateDoc);
        if (result.modifiedCount > 0) {
          const recipientUpdateDoc = {
            $set: {
              balance: recipient.balance + userInfo?.amount,
            },
          };
          const recipientResult = await userCollection.updateOne(
            recipientFilter,
            recipientUpdateDoc
          );
          if (recipientResult.modifiedCount > 0) {
            // generate a random transaction id
            function generateRandomId(length) {
              const characters =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
              let result = "";
              for (let i = 0; i < length; i++) {
                result += characters.charAt(
                  Math.floor(Math.random() * characters.length)
                );
              }
              return result;
            }
            const transactionId = generateRandomId(10);

            // create transaction history
            const transactionHistory = {
              sender: user?.email,
              senderName: user?.name,
              senderMobileNumber: user?.mobileNumber,
              recipient: recipient?.mobileNumber,
              recipientName: recipient?.name,
              amount: userInfo?.amount,
              fee,
              date: Date.now(),
              transactionMethod: "Send Money",
              transactionId,
            };

            const transactionResult = await transactionCollection.insertOne(
              transactionHistory
            );

            return res
              .status(200)
              .json({ acknowledged: true, message: "Money sent successfully" });
          }
        } else {
          return res.status(500).json({ message: "Something went wrong" });
        }

        res.send({ message: "Money sent successfully" });
      } catch (error) {
        res.send({ message: error.message });
      }
    });

    // Cash out api for user and agent
    app.post("/user/cash-out", verifyToken, verifyUser, async (req, res) => {
      const userInfo = req.body;
      const userFilter = { email: userInfo?.userEmail };
      const recipientFilter = { mobileNumber: userInfo?.recipient };

      try {
        // check is user exisit or not
        const user = await userCollection.findOne(userFilter);
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // check is recipient exisit or not
        const recipient = await userCollection.findOne(recipientFilter);
        if (!recipient) {
          return res.status(404).json({ message: "Recipient not found" });
        }

        // check recipient role is agent or not
        if (recipient?.role !== "agent") {
          return res.status(400).json({ message: "Recipient is not a agent" });
        }

        // if user pin is not matched

        const isPasswordValid = await bcrypt.compare(
          String(userInfo?.pin),
          user?.pin
        );

        if (!isPasswordValid) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        // 1.5% of the transaction amount

        let fee = userInfo?.amount * 0.015;

        if (user.balance < userInfo?.amount + fee) {
          return res.status(400).json({ message: "Insufficient balance" });
        }

        // generate a random transaction id
        function generateRandomId(length) {
          const characters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
          let result = "";
          for (let i = 0; i < length; i++) {
            result += characters.charAt(
              Math.floor(Math.random() * characters.length)
            );
          }
          return result;
        }
        const transactionId = generateRandomId(10);

        // create transaction history
        const transactionHistory = {
          sender: user?.email,
          senderName: user?.name,
          senderMobileNumber: user?.mobileNumber,
          recipient: recipient?.mobileNumber,
          recipientName: recipient?.name,
          amount: userInfo?.amount,
          fee,
          date: Date.now(),
          transactionMethod: "Cash Out",
          transactionId,
          requestStatus: "pending",
        };

        const transactionResult = await cashManageCollection.insertOne(
          transactionHistory
        );

        res.send({
          message: "Cash out request successfully",
          acknowledged: true,
        });
      } catch (error) {
        res.send({ message: error.message });
      }
    });

    // Cash In api for user and agent
    app.post("/user/cash-in", verifyToken, verifyUser, async (req, res) => {
      const userInfo = req.body;
      const userFilter = { email: userInfo?.userEmail };
      const recipientFilter = { mobileNumber: userInfo?.recipient };

      try {
        // check is user exisit or not
        const user = await userCollection.findOne(userFilter);
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // check is recipient exisit or not
        const recipient = await userCollection.findOne(recipientFilter);
        if (!recipient) {
          return res.status(404).json({ message: "Recipient not found" });
        }

        // check recipient role is agent or not
        if (recipient?.role !== "agent") {
          return res.status(400).json({ message: "Recipient is not a agent" });
        }

        // if user pin is not matched

        const isPasswordValid = await bcrypt.compare(
          String(userInfo?.pin),
          user?.pin
        );

        if (!isPasswordValid) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        // generate a random transaction id
        function generateRandomId(length) {
          const characters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
          let result = "";
          for (let i = 0; i < length; i++) {
            result += characters.charAt(
              Math.floor(Math.random() * characters.length)
            );
          }
          return result;
        }
        const transactionId = generateRandomId(10);

        // create cash in transaction history
        const transactionHistory = {
          sender: user?.email,
          senderName: user?.name,
          senderMobileNumber: user?.mobileNumber,
          recipient: recipient?.mobileNumber,
          recipientName: recipient?.name,
          amount: userInfo?.amount,
          date: Date.now(),
          transactionMethod: "Cash In",
          transactionId,
          requestStatus: "pending",
        };

        const cashInResult = await cashManageCollection.insertOne(
          transactionHistory
        );

        res.send({
          message: "Cash in request successfully",
          acknowledged: true,
        });
      } catch (error) {
        res.send({ message: error.message });
      }
    });

    // get user transaction history
    app.get(
      "/user/transactions/:email",
      verifyToken,
      verifyUser,
      async (req, res) => {
        const email = req.params.email;
        try {
          const result = await transactionCollection
            .find({ sender: email })
            .sort({ date: -1 })
            .limit(10)
            .toArray();
          res.send(result);
        } catch (error) {
          res.send({ message: error.message });
        }
      }
    );

    // cash manage api for user by agent
    app.get("/cash-manage", verifyToken, verifyAgent, async (req, res) => {
      const size = parseInt(req.query.size);
      const page = parseInt(req.query.page) - 1;
      const search = req.query.search;
      const userMobileNumber = Number(req.query.mobileNumber);
      let query = {
        $or: [
          { name: { $regex: search, $options: "i" } },
          { requestStatus: { $regex: search, $options: "i" } },
        ],
      };

      if (userMobileNumber) {
        query = {
          $and: [query, { recipient: userMobileNumber }],
        };
      }

      const result = await cashManageCollection
        .find(query)
        .sort({ date: -1 })
        .skip(page * size)
        .limit(size)
        .toArray();
      const count = await cashManageCollection.countDocuments(query);
      res.send({ result, count });
    });

    // Cash Manage approval api for user by agent
    app.patch(
      "/agent/approve/:id",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const status = req.body.status;
        try {
          const result = await cashManageCollection.findOne(query);

          if (!result) {
            return res.status(404).json({ message: "Transaction not found" });
          }

          if (result.requestStatus === "success") {
            return res.status(400).json({
              message: "Transaction already done",
            });
          }

          const sender = { email: result?.sender };
          const agent = { mobileNumber: result?.recipient };

          const user = await userCollection.findOne(sender);
          const recipient = await userCollection.findOne(agent);

          if (result.transactionMethod === "Cash Out") {
            const updateDoc = {
              $set: {
                balance: user.balance - result?.amount - result?.fee,
              },
            };

            const updatedResult = await userCollection.updateOne(
              sender,
              updateDoc
            );
            if (updatedResult.modifiedCount > 0) {
              const recipientUpdateDoc = {
                $set: {
                  balance: recipient.balance + result?.amount + result?.fee,
                },
              };
              const recipientResult = await userCollection.updateOne(
                agent,
                recipientUpdateDoc
              );
              if (recipientResult.modifiedCount > 0) {
                // update request status
                const updateDoc = {
                  $set: {
                    requestStatus: status,
                  },
                };
                const updatedResult = await cashManageCollection.updateOne(
                  query,
                  updateDoc
                );
                if (updatedResult.modifiedCount > 0) {
                  // create transaction history
                  const transactionHistory = {
                    sender: user?.email,
                    senderName: user?.name,
                    senderMobileNumber: user?.mobileNumber,
                    recipient: recipient?.mobileNumber,
                    recipientName: recipient?.name,
                    amount: result?.amount,
                    fee: result?.fee,
                    date: Date.now(),
                    transactionMethod: "Cash Out",
                    transactionId: result?.transactionId,
                  };

                  const transactionResult =
                    await transactionCollection.insertOne(transactionHistory);

                  return res.status(200).json({
                    acknowledged: true,
                    message: "Cash out request approved successfully",
                  });
                }
                return res.status(200).json({
                  acknowledged: true,
                  message: "Cash out request approved successfully",
                });
              }
            } else {
              return res.status(500).json({ message: "Something went wrong" });
            }
          }

          if (result.transactionMethod === "Cash In") {
            const updateDoc = {
              $set: {
                balance: user.balance + result?.amount,
              },
            };
            const updatedResult = await userCollection.updateOne(
              sender,
              updateDoc
            );
            if (updatedResult.modifiedCount > 0) {
              const recipientUpdateDoc = {
                $set: {
                  balance: recipient.balance - result?.amount,
                },
              };
              const recipientResult = await userCollection.updateOne(
                agent,
                recipientUpdateDoc
              );
              if (recipientResult.modifiedCount > 0) {
                // update request status
                const updateDoc = {
                  $set: {
                    requestStatus: status,
                  },
                };
                const updatedResult = await cashManageCollection.updateOne(
                  query,
                  updateDoc
                );
                if (updatedResult.modifiedCount > 0) {
                  // create transaction history
                  const transactionHistory = {
                    sender: user?.email,
                    senderName: user?.name,
                    senderMobileNumber: user?.mobileNumber,
                    recipient: recipient?.mobileNumber,
                    recipientName: recipient?.name,
                    amount: result?.amount,
                    fee: result?.fee || 0,
                    date: Date.now(),
                    transactionMethod: "Cash In",
                    transactionId: result?.transactionId,
                  };

                  const transactionResult =
                    await transactionCollection.insertOne(transactionHistory);

                  return res.status(200).json({
                    acknowledged: true,
                    message: "Cash in request approved successfully",
                  });
                }
                return res.status(200).json({
                  acknowledged: true,
                  message: "Cash in request approved successfully",
                });
              }
            } else {
              return res.status(500).json({ message: "Something went wrong" });
            }
          }
        } catch (error) {
          res.send({ message: error.message });
        }
      }
    );

    // get agent transaction history
    app.get(
      "/agent/transactions/:mobileNumber",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const mobileNumber = Number(req.params.mobileNumber);
        try {
          const result = await transactionCollection
            .find({ recipient: mobileNumber })
            .sort({ date: -1 })
            .limit(20)
            .toArray();

          res.send(result);
        } catch (error) {
          res.send({ message: error.message });
        }
      }
    );

    // get admin transaction history
    app.get(
      "/admin/transactions",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const result = await transactionCollection
            .find()
            .sort({ date: -1 })
            .toArray();

          res.send(result);
        } catch (error) {
          res.send({ message: error.message });
        }
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
