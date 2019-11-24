package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	_ "image/jpeg"

	"github.com/dgrijalva/jwt-go"
	"github.com/fasthttp/router"
	"github.com/fasthttp/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/mitchellh/mapstructure"
	"github.com/nfnt/resize"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

const API_KEY = "MmEwOTczMDEtMDJhYS00NWFlLTg1YmItZDhmZDg2ZWM3YjJj"

var JWT_SECRET = []byte("wa wa waa")

var sockets = map[string]*websocket.Conn{}

var upgrader = websocket.FastHTTPUpgrader{
	CheckOrigin: func(ctx *fasthttp.RequestCtx) bool {
		return true
	},
}

type message struct {
	ID        uint       `gorm:"primary_key" json:"_id"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt"`
	Text      string     `json:"text"`
	User      user       `json:"user"`
	ChatID    uint       `json:"chatID"`
}

type login struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	PushToken string `json:"pushToken"`
}

type jwtRequest struct {
	Token string `json:"token"`
}

type notification struct {
	gorm.Model
	UserID uint `json:"user"`
	ChatID uint `json:"chat"`
	Read   bool `json:"read"`
}

type user struct {
	ID               uint           `gorm:"primary_key" json:"_id"`
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
	DeletedAt        *time.Time     `json:"deletedAt"`
	Name             string         `json:"name"`
	Email            string         `json:"email"`
	Password         string         `json:"password"`
	PushToken        string         `json:"pushToken"`
	Avatar           string         `json:"avatar"`
	RegistrationDate string         `json:"registrationDate"`
	Chats            []chat         `gorm:"many2many:user_chats;"`
	Notifications    []notification `json:"notifications"`
}

type chatRequest struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	Avatar  string   `json:"avatar"`
}

type chat struct {
	gorm.Model
	Avatar   string    `json:"avatar"`
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
	db.AutoMigrate(&notification{})

	r := router.New()
	r.GET("/ws", wsHandler)

	log.Fatal(fasthttp.ListenAndServe(":8081", r.Handler))
}

func getUserByEmail(email string) user {
	var u user
	db.Where(&user{Email: email}).First(&u)
	return u
}

func (u *user) notifyUser(text string) {
	url := "https://onesignal.com/api/v1/notifications"

	if u.PushToken == "" {
		return
	}

	var jsonStr = []byte(`{
		"app_id": "3e33e029-dbbf-4915-8c23-0ee2018fbb7a",
		"contents": {"en": "Tienes un nuevo mensaje"},
		"include_player_ids": ["` + u.PushToken + `"]
	}`)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Authorization", "Basic "+API_KEY)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(API_KEY, string(jsonStr), string(body))
}

//

//

//

// // // // // // // // // // //
// WEBSOCKETS IMPLEMENTATION  //
// // // // // // // // // // //

var users []string

type wsMessage struct {
	Command string                 `json:"command"`
	Payload map[string]interface{} `json:"payload"`
}

func wsHandler(ctx *fasthttp.RequestCtx) {
	fmt.Println("new connection")
	err := upgrader.Upgrade(ctx, func(ws *websocket.Conn) {
		defer ws.Close()
		var logged string
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				log.Println(err)
				return
			}
			m := wsRead(msg)
			switch m.Command {
			case "newuser":
				// decode json
				var u user
				mapstructure.Decode(m.Payload, &u)

				u2 := getUserByEmail(u.Email)

				if u2.Email == u.Email {
					wsWrite(ws, wsMessage{
						Command: "notification",
						Payload: map[string]interface{}{
							"isError": true,
							"msg":     "Ya existe un usuario con el mismo email",
						},
					})
					continue
				}

				pwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
				if err != nil {
					fmt.Println(err)
					wsWrite(ws, wsMessage{
						Command: "notification",
						Payload: map[string]interface{}{
							"isError": true,
							"msg":     err.Error(),
						},
					})
					continue
				}
				u.Password = string(pwd)

				fmt.Println("Avatar", u.Avatar[0:50])

				prevAvatar := strings.Split(u.Avatar, ",")[0]
				reader := base64.NewDecoder(base64.StdEncoding, strings.NewReader(strings.Split(u.Avatar, ",")[1]))
				m, _, err := image.Decode(reader)
				if err != nil {
					log.Println(err)
					b64, _ := ioutil.ReadAll(reader)
					log.Println(b64)
				} else {
					newImage := resize.Resize(160, 0, m, resize.Lanczos3)

					// Encode uses a Writer, use a Buffer if you need the raw []byte
					var buff bytes.Buffer
					err = jpeg.Encode(bufio.NewWriter(&buff), newImage, nil)
					if err != nil {
						log.Println(err)
					}
					encodedString := base64.StdEncoding.EncodeToString(buff.Bytes())
					u.Avatar = prevAvatar + "," + encodedString
				}

				// save user
				db.Create(&u)

				wsWrite(ws, wsMessage{
					Command: "notification",
					Payload: map[string]interface{}{
						"isError": false,
						"msg":     "Usuario creado!",
					},
				})
			case "login":
				var l login
				mapstructure.Decode(m.Payload, &l)

				u := getUserByEmail(l.Email)
				err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(l.Password))

				if err != nil {
					fmt.Println("passwords not match, rejected!")
					wsWrite(ws, wsMessage{
						Command: "notification",
						Payload: map[string]interface{}{
							"isError": false,
							"msg":     "Tas equivocao",
						},
					})
					continue
				}

				fmt.Println("passwords match, logged in", u.Email)
				u.PushToken = l.PushToken
				db.Save(&u)

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"email": l.Email,
					"time":  time.Date(2019, 9, 19, 12, 0, 0, 0, time.UTC).Unix(),
				})

				t, err := token.SignedString(JWT_SECRET)
				mw := wsMessage{
					Command: "jwt",
					Payload: map[string]interface{}{
						"token": t,
					},
				}
				wsWrite(ws, mw)
				logged = u.Email
				sockets[u.Email] = ws
			case "jwt":
				var j jwtRequest
				mapstructure.Decode(m.Payload, &j)

				token, err := jwt.Parse(j.Token, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}
					return JWT_SECRET, nil
				})

				if err != nil {
					fmt.Println("token not valid!")
					continue
				}

				var mw wsMessage
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					//TODO: comprobar fecha valida del token
					logged = claims["email"].(string)
					sockets[claims["email"].(string)] = ws
					mw = wsMessage{
						Command: "check",
						Payload: map[string]interface{}{
							"logged": true,
						},
					}
				} else {
					mw = wsMessage{
						Command: "check",
						Payload: map[string]interface{}{
							"logged": false,
						},
					}
					fmt.Println(err)
				}
				wsWrite(ws, mw)
			case "users":
				u := getUserByEmail(logged)

				users := []user{}
				db.Find(&users)

				for i, uu := range users {
					if uu.Email == u.Email {
						users = append(users[:i], users[i+1:]...)
					}
				}

				wsWrite(ws, wsMessage{
					Command: "users",
					Payload: map[string]interface{}{
						"users": users,
					},
				})
			case "chatread":
				u := getUserByEmail(logged)

				var nots []notification
				db.Where("user_id IN (?) AND chat_id IN (?)", u.ID, m.Payload["ID"]).Find(&nots)
				fmt.Println("nots of", u.ID, "and", m.Payload["ID"], nots)

				for _, n := range nots {
					n.Read = true
					fmt.Println("save not, userID", n.UserID, "read", n.Read)
					db.Save(n)
				}
				db.Where("user_id IN (?)", u.ID).Find(&nots)
				wsWrite(ws, wsMessage{
					Command: "notifications",
					Payload: map[string]interface{}{
						"notifications": nots,
					},
				})

			case "newmessage":
				var mm message
				mapstructure.Decode(m.Payload, &mm)

				c := &chat{}
				db.First(c, mm.ChatID)

				u := getUserByEmail(logged)
				mm.User = u

				db.Model(&c).Association("Messages").Append(&mm)

				for _, member := range c.Members {
					us, ok := sockets[member.Email]
					if mm.User.ID != member.ID {
						member.notifyUser(mm.Text)
						not := &notification{
							UserID: member.ID,
							ChatID: c.ID,
							Read:   false,
						}
						db.Save(not)

						var nots []notification
						db.Where("user_id IN (?)", member.ID).Find(&nots)
						//db.Model(member).Related(&nots)
						if ok {
							wsWrite(us, wsMessage{
								Command: "notifications",
								Payload: map[string]interface{}{
									"notifications": nots,
								},
							})
						}
					}
					if ok {
						wsWrite(us, wsMessage{
							Command: "message",
							Payload: map[string]interface{}{
								"message": mm,
							},
						})
					}
				}
			case "messages":
				aux := m.Payload["ID"].(float64)
				id := int(aux)

				c := &chat{}
				db.First(c, id)

				wsWrite(ws, wsMessage{
					Command: "messages",
					Payload: map[string]interface{}{
						"messages": c.Messages,
					},
				})
			case "newchat":
				// decode json
				var c chatRequest
				mapstructure.Decode(m.Payload, &c)

				u := getUserByEmail(logged)

				members := []user{}
				db.Where("email IN (?)", c.Members).Find(&members)
				ch := chat{
					Name:    c.Name,
					Members: append(members, u),
					Avatar:  c.Avatar,
				}

				if len(ch.Members) == 2 {
					sort.Slice(ch.Members, func(i, j int) bool {
						return ch.Members[i].Name < ch.Members[j].Name
					})
					name := ""
					for _, m := range ch.Members {
						name += m.Name
					}
					ch.Name = name
				}

				for _, c2 := range u.Chats {
					if c2.Name == ch.Name {
						wsWrite(ws, wsMessage{
							Command: "notification",
							Payload: map[string]interface{}{
								"isError": true,
								"msg":     "Ya existe un chat con el mismo nombre",
							},
						})
						continue
					}
				}

				u.Chats = append(u.Chats, ch)
				db.Save(&u)
			case "chats":
				var chats []chat
				u := getUserByEmail(logged)

				log.Println("get chats of", u.Name)

				db.Model(&u).Related(&chats, "Chats")

				log.Println("got all chats")

				for k, v := range chats {
					if len(v.Members) == 2 {
						for i, m := range v.Members {
							if m.ID == u.ID {
								if i == 0 {
									v.Name = v.Members[1].Name
									v.Avatar = v.Members[1].Avatar
								} else {
									v.Name = v.Members[0].Name
									v.Avatar = v.Members[0].Avatar
								}
								chats[k] = v
							}
						}
					}
				}

				log.Println("processed all chats")

				wsWrite(ws, wsMessage{
					Command: "chats",
					Payload: map[string]interface{}{
						"chats": chats,
					},
				})
			case "me":
				u := getUserByEmail(logged)

				wsWrite(ws, wsMessage{
					Command: "me",
					Payload: map[string]interface{}{
						"me": u,
					},
				})

				var nots []notification
				db.Where("user_id IN (?)", u.ID).Find(&nots)
				wsWrite(ws, wsMessage{
					Command: "notifications",
					Payload: map[string]interface{}{
						"notifications": nots,
					},
				})
			}
		}
	})

	if err != nil {
		if _, ok := err.(websocket.HandshakeError); ok {
			log.Println(err)
		}
		return
	}
}

func wsRead(p []byte) wsMessage {
	var m wsMessage
	e := json.Unmarshal(p, &m)
	if e != nil {
		log.Println("write:", e)
		return m
	}
	fmt.Println("P", string(p))
	fmt.Printf("WS READ %+v\n", m)
	return m
}

func wsWrite(ws *websocket.Conn, m wsMessage) {
	d, err := json.Marshal(m)
	if err != nil {
		log.Println("write:", err)
	}

	err = ws.WriteMessage(websocket.TextMessage, d)
	if err != nil {
		log.Println("write:", err)
	}
}
