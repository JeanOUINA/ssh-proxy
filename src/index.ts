import * as ssh2 from "ssh2"
import { join } from "path"
import * as fs from "fs"
import * as crypto from "crypto"

console.log("Starting ssh server...")
console.info("Searching host key...")
const keyPath = join(__dirname, "../keys.json")
let keys = new Map()
const keysList = ["rsa"]
if(!fs.existsSync(keyPath)){
    let data = {}
    for(let algo of keysList){
        let key = null
        switch(algo){
            case "ed25519": {
                key = crypto.generateKeyPairSync("ed25519", {
                    publicKeyEncoding: {
                        type: "spki",
                        format: "pem"
                    },
                    privateKeyEncoding: {
                        type: "pkcs8",
                        format: "pem"
                    }
                })
                break
            }
            case "rsa": {
                key = crypto.generateKeyPairSync("rsa", {
                    modulusLength: 2048,
                    publicKeyEncoding: {
                        type: "pkcs1",
                        format: "pem"
                    },
                    privateKeyEncoding: {
                        type: "pkcs1",
                        format: "pem"
                    }
                })
            }
        }
        keys.set(algo, key.privateKey)
        data[algo] = key.privateKey
    }
    fs.writeFileSync(keyPath, JSON.stringify(data))
}else{
    const f = require(keyPath)
    for(let algo of keysList){
        if(!f[algo])continue
        keys.set(algo, f[algo])
    }
}

console.log(`Found ${keys.size} keys`)
const servers = require("../servers.json")
console.log(`Found ${servers.length} servers`)
let privateKey = null
const privateKeyPath = `~/.ssh/id_rsa`
if(fs.existsSync(privateKeyPath)){
    privateKey = fs.readFileSync(privateKeyPath, "utf-8")
}else{
    const keys = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: "pkcs1",
            format: "pem"
        },
        privateKeyEncoding: {
            type: "pkcs1",
            format: "pem"
        }
    })
    fs.mkdirSync(join(privateKeyPath, ".."), {recursive: true})
    fs.writeFileSync(privateKeyPath, keys.privateKey)
    fs.writeFileSync(join(privateKeyPath, "../id_rsa.pub"), keys.publicKey)
}

const sequences = {
    enter: Buffer.from([0x0d]),
    up: Buffer.from([0x1b, 0x5b, 0x41]),
    down: Buffer.from([0x1b, 0x5b, 0x42]),
    escape: Buffer.from([0x03])
}

const server = new ssh2.Server({
    hostKeys: [...keys.values()],
    algorithms: {
        serverHostKey: [...keys.keys()].map(e => "ssh-"+e)
    }
}, client => {
    console.log("Client connect")
    
    const state = {
        type: "menu",
        args: {
            username: "",
            ip: ""
        }
    }

    client.on("close", () => {
        console.log("client close")
    }).on("authentication", ctx => {
        const username = ctx.username
        state.args.username = username
        if(username.startsWith("bssh")){
            const path = join(__dirname, "../sessions", username+".json")
            if(!fs.existsSync(path))return ctx.reject()
            const session = require(path)
            if(session.method !== ctx.method)return ctx.reject()

            switch(ctx.method){
                case "publickey":
                    if(
                        ctx.key.algo === session.key.algo && 
                        ctx.key.data.toString("base64") !== session.key.data
                    )return ctx.reject()
                break
                case "password":
                    if(ctx.password !== session.key.data)return ctx.reject()
                break
                default: {
                    if(ctx.method === "none")break
                    // Unknown authentication; just reject
                    return ctx.reject()
                }
            }

            state.type = "proxy"
            state.args.username = session.username
            state.args.ip = session.ip

            // valid authentication
            return ctx.accept()
        }
        if(ctx.method === "none")return ctx.accept()
        ctx.reject()
    }).on("ready", () => {
        client.on("session", (accept, reject) => {
            const session = accept()
            switch(state.type){
                case "menu": {
                    session.on("shell", async (accept, reject) => {
                        const shell = accept()
                        shell.write(`Welcome to \x1b[33mBunkerSSH\x1b[0m !
\r
This is an utility to access more than one server on the same ssh !\r
Please select what you want to do:\r
\r
`)
        
                        const choices = []
                        for(let server of servers){
                            choices.push({
                                name: server.name,
                                onClick: () => {
                                    shell.write("\x1bc")
                                }
                            })
                        }
                        let awaitUserInput = () => {
                            return new Promise<Buffer>((resolve, reject) => {
                                let clearListeners = () => {
                                    shell.stdin.off("close", closeListener)
                                    shell.stdin.off("data", listener)
                                }
                                let listener = chunk => {
                                    resolve(chunk)
                                    clearListeners()
                                }
                                let closeListener = () => {
                                    reject()
                                    clearListeners()
                                }
                                shell.stdin.on("close", closeListener)
                                shell.stdin.on("data", listener)
                            })
                        }
                        let pos = 0
                        let selected = false
                        let escape = false
                        let writeChoices = () => {
                            shell.write(choices.map((choice, i) => {
                                let text = choice.name
                                if(i === pos)text = `\x1b[4m${text}\x1b[0m`
                                return text+"\n\r"
                            }).join(""))
                        }
                        let clearChoices = () => {
                            let data = "\r"
                            for(let _ of choices){
                                data += "\x1b[K\x1b[A"
                            }
                            shell.write(data)
                        }
                        writeChoices()
                        while(true){
                            if(selected || escape)break
                            const key = await awaitUserInput()
                            for(let seq in sequences){
                                const buffer = sequences[seq]
                                if(!key.equals(buffer))continue
                                switch(seq){
                                    case "down":
                                        pos = (pos+1)%(choices.length)
                                    break
                                    case "up": {
                                        pos--
                                        if(pos < 0)pos = choices.length-1
                                        break
                                    }
                                    case "enter": {
                                        selected = true
                                        break
                                    }
                                    case "escape": {
                                        escape = true
                                        break
                                    }
                                }
                            }
                            if(!selected && !escape){
                                clearChoices()
                                writeChoices()
                            }
                        }
                        if(escape)return shell.write("\n\r"), shell.close()
                        const choice = choices[pos]
                        choice.onClick()
                    }).on("pty", (accept, reject) => {
                        accept()
                    })
                    break
                }
                case "proxy": {
                    let client = undefined
                    let listeners = []
                    let waitForClient:()=>Promise<ssh2.Client> = async () => {
                        if(client === undefined){
                            client = null
                            let c = new ssh2.Client()
                            c.connect({
                                host: state.args.ip,
                                port: 3001,
                                username: state.args.username,
                                privateKey: privateKey
                            })
                            const promise = new Promise<void>((resolve, reject) => {
                                let clear = () => {
                                    c.off("connect", listener)
                                    c.off("error", errorListener)
                                }
                                let listener = () => {
                                    clear()
                                    resolve()
                                }
                                let errorListener = (err) => {
                                    clear()
                                    reject(err)
                                }
                                c.on("connect", listener)
                                c.on("error", errorListener)
                            })
                            try{
                                await promise
                                for(let listener of listeners){
                                    listener[0]()
                                }
                                client = c
                                client.on("error", err => {
                                    console.error(err)
                                })
                                return client
                            }catch(err){
                                for(let listener of listeners){
                                    listener[1](err)
                                }
                                throw err
                            }
                        }else if(client === null){
                            let p
                            const promise = new Promise((resolve, reject) => {
                                p = [resolve, reject]
                            })
                            listeners.push(p)
                            return promise
                        }else{
                            return client
                        }
                    }
                    let pty:ssh2.PseudoTtyInfo
                    session.on("close", () => {
                        if(client)client.destroy()
                    }).on("env", (accept, reject, info) => {
                        console.log(info)
                        if(reject)reject()
                    }).on("exec", async (accept, reject, info) => {
                        try{
                            const client = await waitForClient()
                            client.exec(info.command, (err, channel2) => {
                                if(err)return reject
                                const channel = accept()
                                channel2.pipe(channel)
                                channel2.stderr.pipe(channel)
                                channel.stdin.pipe(channel2)
                                channel2.on("close", () => {
                                    channel.close()
                                })
                                channel2.on("exit", (code, signal, didCoreDump, description) => {
                                    channel.exit(signal, didCoreDump, description)
                                })
                            })
                        }catch{
                            reject()
                        }
                    }).on("pty", async (accept, reject, info) => {
                        try{
                            pty = info
                            accept()
                        }catch{
                            reject()
                        }
                    }).on("shell", async (accept, reject) => {
                        const shell = accept()
                        try{
                            const client = await waitForClient()
                            client.shell(pty ? {
                                cols: pty.cols,
                                height: pty.height,
                                rows: pty.rows,
                                width: pty.width
                            } : false, (err, channel) => {
                                if(err){
                                    shell.stderr.write(err.message+"\n\r")
                                    shell.exit(1)
                                    shell.close()
                                    
                                    return
                                }
                                channel.pipe(shell)
                                shell.stdin.pipe(channel)
                                channel.stderr.pipe(shell)
                                channel.on("close", () => {
                                    shell.close()
                                })
                            })
                        }catch(err){
                            console.error(err)
                            shell.stderr.write("Couldn't connect to the proxied server.\n\r")
                            shell.exit(1)
                            shell.close()
                        }
                    })
                }
            }
        })
    })
})

server.listen(3001)