import norm/sqlite
import jester, asyncdispatch

db("msg.db", "", "", ""):
  type
    User = object
      name: string
      email: string
      password: string
      avatar: string
    Message = object
      text: string
      author: uint
      chatID: uint

withDb:
  createTables(force=true)

settings:
  port = Port(1234)

routes:
  post "/":
    echo "Data:" & $request.body
    withDb:
      var bob = User(
        name: "bob",
        email: "bob@example.com",
        password: "pass",
        avatar: ""
      )
      bob.insert()
    resp "hello"

runForever()