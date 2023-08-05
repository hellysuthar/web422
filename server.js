const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const userService = require("./user-service.js");
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');


const HTTP_PORT = process.env.PORT || 80;

let opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.JWT_SECRET;

passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
    done(null, jwt_payload);
}));

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({"message": msg});
        }).catch((msg) => {
        res.status(422).json({"message": msg});
    });
});

app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            if (user) {
                const payload = {_id: user._id, userName: user.userName};
                const token = jwt.sign(payload, process.env.JWT_SECRET, {
                    expiresIn: '1h', // Optional expiration time
                });
                res.json({message: 'Login successful', token});
            } else {
                res.status(401).json({message: 'Authentication failed'});
            }
        }).catch(msg => {
        res.status(422).json({"message": msg});
    });
});


app.get("/api/user/favourites", passport.authenticate('jwt', {session: false}), (req, res) => {
    userService.getFavourites(req.user._id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({error: msg});
    })

});

app.put("/api/user/favourites/:id", passport.authenticate('jwt', {session: false}), (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
        res.status(422).json({error: msg});
    })
});

app.delete("/api/user/favourites/:id", passport.authenticate('jwt', {session: false}), (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
        res.status(422).json({error: msg});
    })
});

app.get("/api/user/history", passport.authenticate('jwt', {session: false}), (req, res) => {
    userService.getHistory(req.user._id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({error: msg});
    })

});

app.put("/api/user/history/:id", (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
        res.status(422).json({error: msg});
    })
});

app.delete("/api/user/history/:id", (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data)
        }).catch(msg => {
        res.status(422).json({error: msg});
    })
});

userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => {
            console.log("API listening on: " + HTTP_PORT)
        });
    })
    .catch((err) => {
        console.log("unable to start the server: " + err);
        process.exit();
    });