const bodyParser = require("body-parser");
const cors = require("cors");
const express = require("express");
const { v4: uuidv4 } = require("uuid");
const { visit } = require("./bot.js");

const db = require("better-sqlite3")(":memory:");
db.exec(`DROP TABLE IF EXISTS recipe;`);
db.exec(`CREATE TABLE recipe(
	  id TEXT PRIMARY KEY,
    body TEXT
);`);

const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.set("view engine", "ejs");

app.get("/", (_req, res) => {
  res.render("index");
});

app.post("/recipe", (req, res) => {
  const { recipe } = req.body;
  if (recipe) {
    const id = uuidv4();
    const row = db
      .prepare("INSERT INTO recipe (id, body) VALUES (?, ?)")
      .run(id, recipe);

    if (row) return res.json({ id });
  }
  return res.status(400).json({ id: "" });
});

app.get("/recipe/:recipeId", (req, res) => {
  const { recipeId } = req.params;
  const recipe = db
    .prepare("SELECT id, body FROM recipe WHERE id = ?")
    .get(recipeId);
  if (recipe) return res.render("recipe", { recipe: recipe });
  return res.redirect("/");
});

app.post("/share/:recipeId", async (req, res) => {
  if (req.ip === "::1")
    return res
      .status(500)
      .json({ status: false, message: "You shouldn't be doing that!" });
  const { recipeId } = req.params;
  const result = await visit(recipeId);
  return res.json(result);
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log("[*] Server listening at port %s\n", port);
});
