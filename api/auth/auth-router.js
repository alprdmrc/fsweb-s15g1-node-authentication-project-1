// `checkUsernameFree`, `checkUsernameExists` ve `checkPasswordLength` gereklidir (require)
// `auth-middleware.js` deki middleware fonksiyonları. Bunlara burda ihtiyacınız var!
const router = require("express").Router();
const mw = require("./auth-middleware");
const userModel = require("../users/users-model");
const bcrypt = require("bcryptjs");

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status: 201
  {
    "user_id": 2,
    "username": "sue"
  }

  response username alınmış:
  status: 422
  {
    "message": "Username kullaniliyor"
  }

  response şifre 3 ya da daha az karakterli:
  status: 422
  {
    "message": "Şifre 3 karakterden fazla olmalı"
  }
 */

router.post(
  "/register",
  mw.sifreGecerlimi,
  mw.usernameBostami,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const hashedPassword = bcrypt.hashSync(password, 8);
      const insertedUser = await userModel.ekle({
        username: username,
        password: hashedPassword,
      });
      res.status(201).json(insertedUser);
    } catch (error) {
      next(error);
    }
  }
);

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status: 200
  {
    "message": "Hoşgeldin sue!"
  }

  response geçersiz kriter:
  status: 401
  {
    "message": "Geçersiz kriter!"
  }
 */
router.post("/login", mw.usernameVarmi, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (
      req.currentUser &&
      bcrypt.compareSync(password, req.currentUser.password)
    ) {
      req.session.user = req.currentUser;
      res.json({ message: `Hoşgeldin ${username}!` });
    } else {
      res.json({ message: "Geçersiz kriter!" });
    }
  } catch (error) {
    next(error);
  }
});

/**
  3 [GET] /api/auth/logout

  response giriş yapmış kullanıcılar için:
  status: 200
  {
    "message": "Çıkış yapildi"
  }

  response giriş yapmamış kullanıcılar için:
  status: 200
  {
    "message": "Oturum bulunamadı!"
  }
 */

router.get("/logout", (req, res, next) => {
  try {
    if (req.session && req.session.user) {
      const { username } = req.session.user;
      req.session.destroy((err) => {
        if (err) {
          next(err);
        } else {
          res.set(
            "Set-Cookie",
            "cikolatacips=; Path=/; Expires=Mon, 01 Jan 1970 00:00:00"
          );
          res.json({ message: "Çıkış yapildi" });
        }
      });
    } else {
      res.json({ message: "Oturum bulunamadı!" });
    }
  } catch (error) {
    next(error);
  }
});

// Diğer modüllerde kullanılabilmesi için routerı "exports" nesnesine eklemeyi unutmayın.

module.exports = router;
