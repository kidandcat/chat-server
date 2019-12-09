import jwt
import norm/sqlite
import 
  ws, 
  ws/jester_extra, 
  asyncdispatch, 
  asynchttpserver, 
  json, 
  times, 
  tables, 
  nimcrypto, 
  sequtils, 
  os, 
  strutils, 
  jester,
  httpclient,
  smtp

{.reorder:on.}

const LISTEN_PORT = Port(8081)
var secret = "secrettokenwjaksdjwt"

db("msg.db", "", "", ""):
  type
    Chat = object
      name: string
      messages: string
      time: int64
    User = object
      name: string
      email: string
      password: string
      pushtoken: string
      registration: int64
      chats: string
      company: string
      role: string
    Message = object
      text: string
      user: int
      image: string
      video: string
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

settings:
  port = LISTEN_PORT

routes:
  error Exception:
    resp Http500, "Something bad happened: " & exception.msg
  post "/avatar":
    withDb:
      var token = request.formData["token"].body
      var email = ""
      try:
        let jwtToken = token.toJWT()
        if jwtToken.verify(secret):
          email = jwtToken.claims["email"].node.getStr
      except InvalidToken:
        email = ""
      if email != "":
        var user = User.getOne("email=?", [?email])
        discard existsOrCreateDir("public/")
        writeFile("public/" & $user.id & ".png", request.formData["file"].body)
        resp Http200
      resp Http405
  post "/chatavatar":
    withDb:
      var token = request.formData["token"].body
      var chatID = request.formData["chatid"].body
      var email = ""
      try:
        let jwtToken = token.toJWT()
        if jwtToken.verify(secret):
          email = jwtToken.claims["email"].node.getStr
      except InvalidToken:
        email = ""
      if email != "":
        var chat = Chat.getOne(parseInt chatID)
        discard existsOrCreateDir("public/chats")
        writeFile("public/chats/" & $chat.id & ".png", request.formData["file"].body)
        resp Http200
      resp Http405
  post "/sendmessagefile":
    withDb:
      var ext = request.formData["ext"].body
      var token = request.formData["token"].body
      var chatID = request.formData["chatid"].body
      var file = request.formData["file"].body
      var kind = request.formData["type"].body
      var email = ""
      try:
        let jwtToken = token.toJWT()
        if jwtToken.verify(secret):
          email = jwtToken.claims["email"].node.getStr
      except InvalidToken:
        email = ""
      if email != "":
        var u = User.getOne("email=?", [?email])
        var c = Chat.getOne(parseInt chatID)
        discard existsOrCreateDir("public/messages")
        var m = Message(
          text: "",
          image: "",
          video: "", 
          user: u.id,
          createdAt: getTime().toUnix() * 1000
        )
        m.insert()
        if kind == "image":
          m.image = "/messages/" & $m.id & "." & ext
        if kind == "video":
          m.video = "/messages/" & $m.id & "." & ext
        m.update()
        writeFile("public/messages/" & $m.id & "." & ext, file)
        c.messages &= "," & $m.id
        c.update()
        var users = User.getMany(10000)
        users = users.filter(proc (u: User): bool =
          if u.chats.split(",").contains($chatID):
            return true
          return false
        )
        
        var notifyUsers = newSeq[string]()
        echo "Chat users"
        for uu in users:
          # Socket notification
          if connections.hasKey uu.email:
            echo "Message to ", uu.email, ": image"
            asyncCheck connections[uu.email].sen("message", %*{
              "message": {
                "chatID": chatID,
                "text": "",
                "image": m.image,
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
          # Push notification
          if uu.email != email and uu.pushtoken != "" and not connections.hasKey(uu.email):
            echo "Push Notify " & uu.email
            notifyUsers.add $uu.pushtoken
        pushNotification("Nuevo mensaje de "&u.name, m.text, notifyUsers, %*{"chatId": chatID})
        resp Http200
      resp Http405
  get "/ws":
    var email = ""
    try:
      var ws = await newWebSocket(request)
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
                    await ws.sen("check", %*{
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
                if not email.contains("@") or not email.contains("."):
                  await ws.sen("registererror", %*{
                    "error": "El email no es válido"
                  })
                  continue
                if name.len < 2:
                  await ws.sen("registererror", %*{
                    "error": "El nombre es demasiado corto"
                  })
                  continue
                if password.len < 5:
                  await ws.sen("registererror", %*{
                    "error": "La contraseña es demasiado corta"
                  })
                  continue
                var u = User(
                  name: name,
                  email: email,
                  password: $keccak_256.digest(password),
                  pushtoken: "",
                  registration: getTime().toUnix,
                  chats: ""
                )
                u.insert()
              # # # # #
              # LOGIN #
              # # # # #
              of "login":
                var lemail = p["email"].getStr
                var password = p["password"].getStr
                try:
                  var u = User.getOne(cond="email=?", params=[dbValue lemail])
                  if u.name == "":
                    await ws.sen("loginerror", %*{
                      "error": "El usuario no existe"
                    })
                    continue
                  if u.password == $keccak_256.digest(password):
                    email = lemail
                    connections[email] = ws
                    await ws.sen("jwt", %*{
                      "token": newToken(lemail)
                    })
                  else:
                    await ws.sen("loginerror", %*{
                      "error": "Contraseña incorrecta"
                    })
                except:
                  echo getCurrentExceptionMsg()
                  await ws.sen("loginerror", %*{
                    "error": "El usuario no existe"
                  })
              # # # # #
              # LOGIN #
              # # # # #
              of "pushtoken":
                var token = p["token"].getStr
                var u = User.getOne("email=?", [?email])
                u.pushtoken = token
                u.update()
              # # # # #
              # COMMENT #
              # # # # #
              of "comment":
                var text = p["text"].getStr
                var msg = createMessage("Comentario Chat de " & email, text, @["jairocaro@msn.com", "olgshestakova@gmail.com"])
                let smtpConn = newSmtp(useSsl = true, debug=true)
                smtpConn.connect("smtp.gmail.com", Port 465)
                smtpConn.auth("olgshestakova@gmail.com", "No.culpes.al.karma")
                smtpConn.sendmail("olgshestakova@gmail.com", @["jairocaro@msn.com", "olgshestakova@gmail.com"], $msg)
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
                await ws.sen("users", %*{
                  "users": users
                })
              # # # # # # # #
              # MODIFY USER #
              # # # # # # # #
              of "modifyuser":
                var id = p["id"].getInt
                var name = p["name"].getStr
                var email = p["email"].getStr
                var password = p["password"].getStr
                var company = p["company"].getStr
                var role = p["role"].getStr

                var u = User.getOne(id)
                if name != "":
                  u.name = name
                if email != "":
                  u.email = email
                if password != "":
                  u.password = $keccak_256.digest(password)
                if company != "":
                  u.company = company
                if role != "":
                  u.role = role
                u.update()
                await ws.sen("me", %*{
                  "me": u
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
                c.time =  getTime().toUnix() * 1000
                c.update()
                
                var users = User.getMany(100)
                users = users.filter(proc (u: User): bool =
                  if u.chats.split(",").contains($chatID):
                    return true
                  return false
                )
                
                var notifyUsers = newSeq[string]()
                for uu in users:
                  # Socket notification
                  if connections.hasKey uu.email:
                    echo "Message to ", uu.email, ": ", m.text
                    await connections[uu.email].sen("message", %*{
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
                  # Push notification
                  if uu.email != email and uu.pushtoken != "" and not connections.hasKey(uu.email):
                    echo "Push Notify " & uu.email
                    notifyUsers.add $uu.pushtoken
                pushNotification("Nuevo mensaje de "&u.name, m.text, notifyUsers, %*{"chatId": chatID})
              # # # # # # #
              # MESSAGES  #
              # # # # # # #
              of "messages":
                var chatID = p["chatID"].getInt
                var c = Chat.getOne(chatID)
                var msgs = c.messages.strip()
                var messages: seq[JsonNode]
                for mid in msgs.split(","):
                  if mid != "":
                    try:
                      var m = Message.getOne(parseInt mid)
                      var u = User.getOne(m.user) # TODO: cache this
                      var jm = %*{
                        "chatID": chatID,
                        "_id": m.id,
                        "text": m.text,
                        "createdAt": m.createdAt,
                        "user": {
                          "_id": u.id,
                          "name": u.name,
                        }
                      }
                      if m.image != "":
                        jm["image"] = %m.image
                      if m.video != "":
                        jm["video"] = %m.video
                      messages.add jm
                    except:
                      echo getCurrentExceptionMsg()
                await ws.sen("messages", %*{
                  "messages": messages
                })
              # # # # # # #
              # NEW CHAT  #
              # # # # # # #
              of "newchat":
                var name = p["name"].getStr
                var members = p["members"]
                var user = User.getOne("email=?", email)
                var chat = Chat(
                  name: name,
                  messages: ""
                )

                if len(members) < 2:
                  var m = User.getOne("email=?", members[0].getStr)
                  var nameA = user.name & "|" & m.name
                  var nameB = m.name & "|" & user.name
                  try:
                    var c = Chat.getOne("name=?", nameA)
                    await ws.sen("open", %*{
                      "chat": c.id
                    })
                    continue
                  except:
                    echo getCurrentExceptionMsg()
                  try:
                    var c = Chat.getOne("name=?", nameB)
                    await ws.sen("open", %*{
                      "chat": c.id
                    })
                    continue
                  except:
                    echo getCurrentExceptionMsg()
                  chat.name = nameA
                  

                try:
                  discard Chat.getOne("name=?", chat.name)
                  # ws.errored("Ya existe un chat con ese nombre")
                  continue
                except:
                  echo getCurrentExceptionMsg()
                chat.insert()

                user.chats &= (if user.chats == "": $chat.id else: "," & $chat.id)
                user.update()

                echo "New chat ", $chat
                echo "Chats updated for ", user.email, ": ", user.chats

                for mid in members:
                  var m = User.getOne("email=?", mid.getStr)
                  m.chats &= (if m.chats == "": $chat.id else: "," & $chat.id)
                  m.update()
                  if connections.hasKey m.email:
                    var mchats = Chat.getMany(100, 0, "id IN (?)", [dbValue m.chats])
                    await connections[m.email].sen("chats", %*{
                      "chats": mchats
                    })
              # # # # #
              # CHATS #
              # # # # #
              of "chats":
                var chatsRes = newSeq[JsonNode]()
                var user = User.getOne("email=?", email)
                var params = newSeq[DbValue]()
                var queryArgs = ""
                for c in user.chats.split(","):
                  params.add ?c
                  queryArgs &= (if queryArgs=="": "?" else: ", ?")
                var chats = Chat.getMany(100, 0, "id IN ("&queryArgs&")", params)
                for c in chats.mitems:
                  var isGroup = false
                  try:
                    var nameLeft = c.name.split("|")[0]
                    var nameRight = c.name.split("|")[1]
                    if user.name == nameLeft:
                      c.name = nameRight
                    elif user.name == nameRight:
                      c.name = nameLeft
                  except:
                    isGroup = true
                    echo getCurrentExceptionMsg()
                  chatsRes.add %*{
                    "id": c.id,
                    "name": c.name,
                    "messages": c.messages,
                    "isGroup": isGroup,
                    "time": c.time
                  }
                await ws.sen("chats", %*{
                  "chats": chatsRes
                })
              # # # #
              # ME  #
              # # # #
              of "me":
                var user = User.getOne("email=?", email)
                await ws.sen("me", %*{
                  "me": user
                })
          except:
            echo email, " disconnected ", getCurrentExceptionMsg()
            connections.del(email)
    except:
      echo email, " disconnected ", getCurrentExceptionMsg()
      connections.del(email)

proc sen(ws: WebSocket, command: string, payload: JsonNode) {.async.} =
  echo "<<<------", command, $payload
  if ws.readyState == Open:
    await ws.send($ %*{
      "command": command,
      "payload": payload
    })

proc pushNotification(title: string, body: string, token: seq[string], data: JsonNode) =
  if len(token) < 1:
    return
  let client = newHttpClient()
  client.headers = newHttpHeaders({ "Content-Type": "application/json" })
  var body = %*{
    "to": token,
    "title": title,
    "body": body,
    "data": data
  }
  echo "PushNotification body " & $body
  let response = client.request("https://exp.host/--/api/v2/push/send", httpMethod = HttpPost, body = $body)
  echo response.status & " " & response.body

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
