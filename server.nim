import jwt
import norm/sqlite
import ws, asyncdispatch, asynchttpserver, json, times, tables, nimcrypto, sequtils, os, strutils

{.reorder:on.}

const PORT = Port(8081)
var secret = "secrettokenwjaksdjwt"

db("msg.db", "", "", ""):
  type
    Chat = object
      name: string
      avatar: string
      messages: string
    User = object
      name: string
      email: string
      password: string
      avatar: string
      pushtoken: string
      registration: int64
      chats: string
    Message = object
      text: string
      user: int
      createdAt: int64
    Notification = object
      user{.fk: User.}: int
      chat{.fk: Chat.}: int
      read: bool

withDb:
  if paramCount() > 0:
    var createTablesDB = paramStr(1)
    if createTablesDB == "--create":
      createTables(force=true)
    elif createTablesDB == "--update":
      createTables(force=false)
    else:
      echo "createTablesDB " & createTablesDB

var connections = newTable[string, WebSocket]()

proc cb(req: Request) {.async, gcsafe.} =
  if req.url.path == "/ws":
    try:
      var ws = await newWebSocket(req)
      var email = ""
      withDb:
        while ws.readyState == Open:
          let packet = await ws.receiveStrPacket()
          try:
            var m = parseJson packet
            var p = m{"payload"}
            echo "------>>>", packet.substr(0, 100)
            case m["command"].getStr:
              # # # #
              # JWT #
              # # # #
              of "jwt":
                try:
                  let jwtToken = p["token"].getStr.toJWT()
                  if jwtToken.verify(secret):
                    email = jwtToken.claims["email"].node.getStr
                    connections[email] = ws
                    ws.sen("check", %*{
                      "logged": true
                    })
                  else:
                    email = ""
                except InvalidToken:
                  email = ""
              # # # # # # #
              # NEW USER  #
              # # # # # # #
              of "newuser":
                var name = p["name"].getStr
                var email = p["email"].getStr
                var password = p["password"].getStr
                var avatar = p{"avatar"}.getStr
                echo "password hashed: " & $keccak_256.digest(password)
                var u = User(
                  name: name,
                  email: email,
                  password: $keccak_256.digest(password),
                  avatar: "",
                  pushtoken: "",
                  registration: getTime().toUnix,
                  chats: ""
                )
                u.insert()
                ws.notify("Usuario creado")
              # # # # #
              # LOGIN #
              # # # # #
              of "login":
                var lemail = p["email"].getStr
                var password = p["password"].getStr
                var pushtoken = p{"pushtoken"}.getStr
                try:
                  var u = User.getOne(cond="email=?", params=[dbValue lemail])
                  if u.password == $keccak_256.digest(password):
                    email = lemail
                    connections[email] = ws
                    ws.sen("jwt", %*{
                      "token": newToken(lemail)
                    })
                  else:
                    ws.errored("Datos incorrectos")
                except:
                  echo getCurrentExceptionMsg()
                  ws.errored("Datos incorrectos")
              # # # # #
              # USERS #
              # # # # #
              of "users":
                var users = User.getMany(100)
                users = users.filter(proc (u: User): bool =
                  if u.email == email:
                    return false
                  return true
                )
                ws.sen("users", %*{
                  "users": users
                })
              # # # # # # #
              # CHAT READ #
              # # # # # # #
              of "chatread":
                var chatID = p["ID"].getInt
                var user = User.getOne("email=?", email)
                var notif = Notification.getOne(cond="user=? AND chat=?", params=[dbValue chatID, dbValue user.id])
                echo repr notif
              # # # # # # # #
              # NEW MESSAGE #
              # # # # # # # #
              of "newmessage":
                var text = p["text"].getStr
                var chatID = p["chatID"].getInt
                var u = User.getOne("email=?", email)
                var m = Message(
                  text: text,
                  user: u.id,
                  createdAt: getTime().toUnix() * 1000
                )
                m.insert()
                echo "Message created " & $m.id
                var c = Chat.getOne(chatID)
                c.messages &= "," & $m.id
                c.update()
                
                var users = User.getMany(100)
                users = users.filter(proc (u: User): bool =
                  if u.chats.split(",").contains($chatID):
                    return true
                  return false
                )
                
                for uu in users:
                  if connections.hasKey uu.email:
                    connections[uu.email].sen("message", %*{
                      "message": {
                        "chatID": chatID,
                        "text": m.text,
                        "_id": m.id,
                        "createdAt": m.createdAt,
                        "user": {
                          "_id": m.user,
                          "name": u.name,
                          # "avatar": {
                          #   "uri": u.avatar
                          # }
                        }
                      }
                    })
              # # # # # # #
              # MESSAGES  #
              # # # # # # #
              of "messages":
                var chatID = p["chatID"].getInt
                var c = Chat.getOne(chatID)
                var msgs = c.messages.strip()
                var messages: seq[JsonNode]
                for mid in msgs.split(","):
                  echo "mid", mid
                  if mid != "":
                    try:
                      var m = Message.getOne(parseInt mid)
                      var u = User.getOne(m.user)
                      messages.add %*{
                        "chatID": chatID,
                        "_id": m.id,
                        "text": m.text,
                        "createdAt": m.createdAt,
                        "user": {
                          "_id": u.id,
                          "name": u.name,
                          # "avatar": {
                          #   "uri": u.avatar
                          # }
                        }
                      }
                    except:
                      echo getCurrentExceptionMsg()
                ws.sen("messages", %*{
                  "messages": messages
                })
              # # # # # # #
              # NEW CHAT  #
              # # # # # # #
              of "newchat":
                var name = p["name"].getStr
                var members = p["members"]
                var avatar = p{"avatar"}.getStr
                var user = User.getOne("email=?", email)
                var chat = Chat(
                  name: name,
                  avatar: avatar,
                  messages: ""
                )

                if len(members) < 2:
                  var m = User.getOne("email=?", members[0].getStr)
                  var nameA = user.name & "|" & m.name
                  var nameB = m.name & "|" & user.name
                  try:
                    discard Chat.getOne("name=?", nameA)
                    ws.errored("Chat already exists " & nameA)
                    continue
                  except:
                    echo getCurrentExceptionMsg()
                  try:
                    discard Chat.getOne("name=?", nameB)
                    ws.errored("Chat already exists " & nameB)
                    continue
                  except:
                    echo getCurrentExceptionMsg()
                  chat.name = nameA
                  

                try:
                  discard Chat.getOne("name=?", chat.name)
                  ws.errored("Chat already exists " & chat.name)
                  continue
                except:
                  echo getCurrentExceptionMsg()
                chat.insert()

                user.chats &= (if user.chats == "": $chat.id else: "," & $chat.id)
                user.update()

                for mid in members:
                  var m = User.getOne("email=?", mid.getStr)
                  m.chats &= (if m.chats == "": $chat.id else: "," & $chat.id)
                  m.update()
                  if connections.hasKey m.email:
                    var mchats = Chat.getMany(100, 0, "id IN (?)", [dbValue m.chats])
                    connections[m.email].sen("chats", %*{
                      "chats": mchats
                    })
              # # # # #
              # CHATS #
              # # # # #
              of "chats":
                var chatsRes = newSeq[JsonNode]()
                var user = User.getOne("email=?", email)
                var chats = Chat.getMany(100, 0, "id IN (?)", [dbValue user.chats])
                for c in chats.mitems:
                  try:
                    var nameLeft = c.name.split("|")[0]
                    var nameRight = c.name.split("|")[1]
                    if user.name == nameLeft:
                      c.name = nameRight
                    elif user.name == nameRight:
                      c.name = nameLeft
                  except:
                    echo getCurrentExceptionMsg()
                  chatsRes.add %*{
                    "name": c.name,
                    "avatar": c.avatar,
                    "messages": c.messages,
                    "users": "" # TODO users of the chat
                  }
                ws.sen("chats", %*{
                  "chats": chatsRes
                })
              # # # #
              # ME  #
              # # # #
              of "me":
                var user = User.getOne("email=?", email)
                ws.sen("me", %*{
                  "me": user
                })
          except:
            echo getCurrentExceptionMsg()
            echo getCurrentException().getStackTrace()
            ws.errored(getCurrentExceptionMsg())
    except:
      echo getCurrentExceptionMsg()
      echo getCurrentException().getStackTrace()
  await req.respond(Http404, "")

proc notify(ws: WebSocket, msg: string) =
  asyncCheck ws.send($ %*{
    "command": "notification",
    "payload": {
      "msg": msg,
      "isError": false
    }
  })

proc errored(ws: WebSocket, msg: string) =
  asyncCheck ws.send($ %*{
    "command": "notification",
    "payload": {
      "msg": msg,
      "isError": true
    }
  })

proc sen(ws: WebSocket, command: string, payload: JsonNode) =
  echo "<<<------", command, ($payload).substr(0, 100)
  asyncCheck ws.send($ %*{
    "command": command,
    "payload": payload
  })

proc newToken(email: string): string =
  var token = toJWT(%*{
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "claims": {
      "email": email,
      "exp": (getTime() + 1.days).toSeconds().int
    }
  })
  token.sign(secret)
  return $token

var server = newAsyncHttpServer()
echo "Listening on port " & repr PORT
waitFor server.serve(PORT, cb)