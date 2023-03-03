import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import Database from "better-sqlite3";
import MOVIES from "./movies.js";

const FLAG = process.env.FLAG ?? "S2G{dummy_flag}";

const db = new Database("db.sqlite3");
db.exec(`DROP TABLE IF EXISTS flag;`);
db.exec(`CREATE TABLE flag(
    flag TEXT
);`);
db.exec(`INSERT INTO flag (flag) VALUES (
    '${FLAG}'
)`);
db.exec(`DROP TABLE IF EXISTS movies;`);
db.exec(`CREATE TABLE movies(
		id PRIMAY KEY,
    title TEXT NOT NULL,
    release_date TEXT NOT NULL,
    poster_path TEXT NOT NULL,
    overview TEXT NOT NULL,
    score INTEGER DEFAULT 0
);`);
try {
	const insert = db.prepare(
		"INSERT INTO movies (title, release_date, poster_path, overview, score) VALUES (@title, @release_date, @poster_path, @overview, @score)"
	);
	const insertMany = db.transaction((movies) => {
		for (const movie of movies) insert.run(movie);
	});
	insertMany(MOVIES);
} catch (error) {
	console.log(error);
}

const app = express();
app.use(cors());
// Configuring body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// Configuring json response
app.set("json spaces", 2);

// View engine setup
app.set("view engine", "ejs");
app.use(express.static("public"));

app.post("/", async (req, res) => {
	const input = req.body.input ?? "";
	const debug = Boolean(req.body.debug === "1") ?? false;

	const query = `SELECT * FROM movies WHERE title LIKE '%${input}%';`;
	try {
		const movies = db.prepare(query).all();
		console.log(movies);
		if (movies) {
			return res.render("index", {
				movies: movies,
				debug: debug ? `${query}` : "",
			});
		} else throw new Error("Couldn't execute SQL statement");
	} catch {
		if (debug) return res.redirect(`/?debug=${query}`);
		else return res.redirect(`/`);
	}
});

app.get("/", (req, res) => {
	res.render("index", {
		movies: [],
		debug: (req.query.debug ?? "").toString().replace(/>|</g),
	});
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
	console.log("[*] Server listening at port %s\n", port);
});
