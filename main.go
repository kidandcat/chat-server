package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/fasthttp/router"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

type message struct {
	gorm.Model
	Text   string `json:"text"`
	Author uint   `json:"author"`
	ChatID uint
}

type login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type user struct {
	gorm.Model
	Name             string `json:"name"`
	Email            string `json:"email"`
	Password         string `json:"password"`
	RegistrationDate string `json:"registrationDate"`
	Chats            []chat `gorm:"many2many:user_chats;"`
}

type chatRequest struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type chat struct {
	gorm.Model
	Name     string    `json:"name"`
	Members  []user    `json:"members" gorm:"many2many:user_chats;"`
	Messages []message `gorm:"foreignkey:ChatID"`
}

var db *gorm.DB

func main() {
	var err error
	db, err = gorm.Open("sqlite3", "chat.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db = db.Set("gorm:auto_preload", true)
	db.AutoMigrate(&message{})
	db.AutoMigrate(&user{})
	db.AutoMigrate(&chat{})

	r := router.New()
	r.GET("/messages", messagesHandler)
	r.POST("/newmessage", newMessageHandler)
	r.GET("/chats", chatsHandler)
	r.POST("/newchat", newChatHandler)
	r.POST("/newuser", newUserHandler)
	r.POST("/login", loginHandler)
	r.GET("/logged", loggedHandler)
	r.GET("/logout", logoutHandler)
	r.GET("/users", usersHandler)
	r.GET("/me", meHandler)

	r.OPTIONS("/login", cors)
	r.OPTIONS("/newuser", cors)
	r.OPTIONS("/newchat", cors)
	r.OPTIONS("/newmessage", cors)

	log.Fatal(fasthttp.ListenAndServe(":8081", r.Handler))
}

/*
	Helpers Section
*/

func setCorsHeaders(ctx *fasthttp.RequestCtx) {
	origin := string(ctx.Request.Header.Peek("origin"))
	ori := string(ctx.Host())
	if origin != "" {
		ori = origin
	}
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type")
	ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", ori)
}

func cors(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	ctx.Response.SetStatusCode(fasthttp.StatusOK)
}

func getUserByEmail(email string) user {
	var u user
	db.Where(&user{Email: email}).First(&u)
	return u
}

func getUser(ctx *fasthttp.RequestCtx) user {
	email := string(ctx.Request.Header.Cookie("email"))
	return getUserByEmail(email)
}

func isNotLogged(ctx *fasthttp.RequestCtx) bool {
	lc := ctx.Request.Header.Cookie("email")
	if string(lc) == "" {
		ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
		return true
	}
	return false
}

func okError(ctx *fasthttp.RequestCtx, err error) bool {
	if err != nil {
		ctx.Response.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintln(ctx, err.Error())
		return true
	}
	ctx.Response.SetStatusCode(fasthttp.StatusOK)
	return false
}

/*
	Login Section
*/

func logoutHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	ctx.Response.Header.DelClientCookie("email")
	ctx.Response.SetStatusCode(fasthttp.StatusOK)
}

func loggedHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	isNotLogged(ctx)
}

func loginHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	var l login
	err := json.Unmarshal(ctx.PostBody(), &l)
	if err != nil {
		okError(ctx, err)
		return
	}

	u := getUserByEmail(l.Email)
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(l.Password))

	if err == nil {
		fmt.Printf("passwords match, logged in, saving email: %v in cookie\n", u.Email)
		c := fasthttp.AcquireCookie()
		defer fasthttp.ReleaseCookie(c)
		c.SetKey("email")
		c.SetValue(u.Email)
		ctx.Response.Header.SetCookie(c)
		ctx.Response.SetStatusCode(fasthttp.StatusOK)
		return
	}
	fmt.Println("passwords not match, rejected!")
	ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
}

/*
	User Section
*/

func newUserHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)

	// decode json
	var u user
	json.Unmarshal(ctx.PostBody(), &u)

	u2 := getUserByEmail(u.Email)

	log.Println("u2.Email == u.Email", u2.Email, u.Email)
	if u2.Email == u.Email {
		ctx.Response.SetStatusCode(fasthttp.StatusConflict)
		fmt.Fprintln(ctx, "An user with that email already exists")
		return
	}

	pwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if okError(ctx, err) {
		return
	}
	u.Password = string(pwd)

	// save user
	db.Create(&u)

	okError(ctx, nil)
}

func usersHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	if isNotLogged(ctx) {
		return
	}

	u := getUser(ctx)

	users := []user{}
	db.Find(&users)

	for i, uu := range users {
		if uu.Email == u.Email {
			users = append(users[:i], users[i+1:]...)
		}
	}

	b, err := json.Marshal(users)
	if okError(ctx, err) {
		return
	}

	fmt.Fprintf(ctx, "%v", string(b))
}

func meHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	if isNotLogged(ctx) {
		return
	}

	u := getUser(ctx)

	b, err := json.Marshal(u)
	if okError(ctx, err) {
		return
	}

	fmt.Fprintf(ctx, "%v", string(b))
}

/*
	Chats Section
*/

func newChatHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	if isNotLogged(ctx) {
		return
	}

	u := getUser(ctx)

	// decode json
	var c chatRequest
	err := json.Unmarshal(ctx.PostBody(), &c)
	if okError(ctx, err) {
		return
	}

	for _, c2 := range u.Chats {
		log.Println("c2.Name == c.Name", c2.Name, c.Name)
		if c2.Name == c.Name {
			ctx.Response.SetStatusCode(fasthttp.StatusConflict)
			fmt.Fprintln(ctx, "A chat with that name already exists")
			return
		}
	}

	members := []user{}
	db.Where("email IN (?)", c.Members).Find(&members)
	ch := chat{
		Name:    c.Name,
		Members: members,
	}

	u.Chats = append(u.Chats, ch)
	db.Save(&u)
}

func chatsHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	if isNotLogged(ctx) {
		return
	}

	var chats []chat
	u := getUser(ctx)

	db.Model(&u).Related(&chats, "Chats")

	b, err := json.Marshal(chats)
	if okError(ctx, err) {
		return
	}

	fmt.Fprintf(ctx, "%v", string(b))
}

/*
	Messages Section
*/

func newMessageHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	if isNotLogged(ctx) {
		return
	}

	id, err := strconv.Atoi(string(ctx.FormValue("id")))
	if okError(ctx, err) {
		return
	}

	c := &chat{}
	db.First(c, id)

	var m message
	err = json.Unmarshal(ctx.PostBody(), &m)

	u := getUser(ctx)
	m.Author = u.ID

	db.Model(&c).Association("Messages").Append(&m)

	okError(ctx, err)
}

func messagesHandler(ctx *fasthttp.RequestCtx) {
	setCorsHeaders(ctx)
	if isNotLogged(ctx) {
		return
	}

	id, err := strconv.Atoi(string(ctx.FormValue("id")))
	if okError(ctx, err) {
		return
	}

	c := &chat{}
	db.First(c, id)

	err = json.NewEncoder(ctx).Encode(c.Messages)
	if okError(ctx, err) {
		return
	}

	ctx.Response.Header.Set("Content-Type", "application/json")
}
