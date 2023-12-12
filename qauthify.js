/*
QAuthify auth platform
Ensure that PORT, ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET, MONGODB_URI environment variables are set
SSL implementation is the responsibility of the end user.
(c) Faraaz Jan, 2023
*/

require('dotenv').config()
const express = require('express')
const app = express()
const Usertype = require('./models/usertype')
const shajs = require('sha.js')
const https = require('https')

const jwt = require('jsonwebtoken')

app.use(express.json())

const TOKEN_LIFETIME_SEC = 900 //how long the connection should last before the client must request a new access token
//const privateKey = fs.readFileSync('./ssl/privatekey.pem', 'utf8')
//const certificate = fs.readFileSync('./ssl/certificate.pem', 'utf8')

const resource = [
    {
        userIdOwner: 'faraazJan',
        content: '(1) My content here'
    },
    {
        userIdOwner: 'exampleuseridhere3',
        content: '(2) My content here'
    },
    {
        userIdOwner: 'exampleuseridhere2',
        content: '(3) My content here'
    }
]

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(token === null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        req.user = user
        next()
    })
}

const getTokenInfo = (req, res, next) => {
    if(!req.body.token) return res.sendStatus(401)
    req.tokeninfo = jwt.decode(req.body.token)
    next()
}

const checkuserexists = (req, res, next) => {
    Usertype.findOne({ usernameLow: req.body.username.toLowerCase() })
        .then((existUser) => {
            if(existUser) return res.sendStatus(409)
            next()
        }).catch(() => {
            next()
        })
}

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: `${TOKEN_LIFETIME_SEC}s` })
}

app.get('/resource', authenticateToken, (req, res) => { //can be migrated to a seperate content server in order to seperate login/content traffic
    res.json(resource.filter(item => item.userIdOwner === req.user.userId)) //only serve content the user is allowed to view.
})

app.get('/accountinfo', authenticateToken, (req, res) => { //can be migrated to a seperate content server in order to seperate login/content traffic

    Usertype.findById(req.user.userId)
        .then(userdata => {
            const accountInfo = {
                username: userdata.username
            }
            res.json(accountInfo)
        }).catch(error => {
            res.sendStatus(404)
        })
})

app.delete('/logout', getTokenInfo, (req, res) => {
    
    Usertype.findById(req.tokeninfo.userId)
        .then(userData => {
            userData.refreshTokens = userData.refreshTokens.filter(refreshToken => refreshToken.token !== req.body.token)
            userData.save()
                .then(() => {
                    res.sendStatus(204)
                    console.log(`logout by user ${userData.username}`)
                }).catch(error => {
                    res.sendStatus(500)
                })
        })
        .catch(error => {
            res.sendStatus(403)
        })
})

app.post('/login', (req, res) => {
    const body = req.body

    Usertype.findOne({ username: body.username })
        .then(usertype => {

            const userValidate = {userId: usertype._id.toString()} //optionally specify an expiration
            const accessToken = generateAccessToken(userValidate)
            const refreshToken = jwt.sign(userValidate, process.env.REFRESH_TOKEN_SECRET)

            hashPassword = shajs('sha256').update(`${body.password}${usertype._id.toString()}`).digest('hex')

            if(hashPassword!==usertype.hashPassword) {
                return res.sendStatus(403)
            }

            Usertype.findByIdAndUpdate(usertype._id.toString(), {$push: {
                refreshTokens: {
                    token: refreshToken,
                    creationDate: Date.now(),
                    lastUsageDate: Date.now(),
                    lastIp: req.socket.remoteAddress,
                }
            }}).then(updatedUsertype => {
                console.log(`new login to user ${updatedUsertype.username}`)
                res.json({
                    accessToken: accessToken,
                    refreshToken: refreshToken
                })
            }).catch(error => {
                res.sendStatus(500)
            })
        })
        .catch(error => {
            res.sendStatus(403)
        })
})

app.post('/signup', checkuserexists, (req, res) => {
    const body = req.body

    if(!(body.username && body.password)) return response.sendStatus(404)

    const newuser = new Usertype({
        username: body.username,
        usernameLow: body.username.toLowerCase()
    })
    newuser.hashPassword = shajs('sha256').update(`${body.password}${newuser._id.toString()}`).digest('hex')

    const identifier = {userId: newuser._id.toString()} //optionally specify an expiration
    const accessToken = generateAccessToken(identifier)
    const refreshToken = jwt.sign(identifier, process.env.REFRESH_TOKEN_SECRET)
    newuser.refreshTokens = [{
            token: refreshToken,
            creationDate: Date.now(),
            lastUsageDate: Date.now(),
            lastIp: req.socket.remoteAddress,
        }]

    newuser.save().then(savedUser => {
        console.log(`new user created ${body.username}`)
        res.json({
            accessToken: accessToken,
            refreshToken: refreshToken
        })
    }).catch(error => {
        console.log(error)
        res.sendStatus(400)
    })
})

app.delete('/delacc', getTokenInfo, (req, res) => {
    const refreshToken = req.body.token
    if(refreshToken === null) return res.sendStatus(401)

    Usertype.findById(req.tokeninfo.userId)
    .then(userData => {
        if(!userData.refreshTokens.map(refreshTokenItem => refreshTokenItem.token).includes(refreshToken)) return res.sendStatus(403)
        
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if(err) return res.sendStatus(403)
            Usertype.findByIdAndDelete(req.tokeninfo.userId)
                .then(() => {
                    res.sendStatus(204)
                    console.log(`deleted account ${userData.username}`)
                }).catch(() => {
                    res.sendStatus(404)
                })
        })
    }).catch(error => {
        res.sendStatus(404)
    })
})

app.post('/token', getTokenInfo, (req, res) => {
    const refreshToken = req.body.token
    if(refreshToken === null) return res.sendStatus(401)

    Usertype.findById(req.tokeninfo.userId)
    .then(userData => {
        if(!userData.refreshTokens.map(refreshTokenItem => refreshTokenItem.token).includes(refreshToken)) return res.sendStatus(403)
        
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if(err) return res.sendStatus(403)
            
            userData.refreshTokens = userData.refreshTokens.map(refreshTokenItem => (refreshTokenItem.token===refreshToken ? {
                token: refreshTokenItem.token,
                creationDate: refreshTokenItem.creationDate,
                lastUsageDate: Date.now(),
                lastIp: req.socket.remoteAddress
            } : refreshTokenItem))
            
            userData.save()
                .then(() => {
                    const accessToken = generateAccessToken({userId: user.userId}) //optionally add expiration
                    console.log(`new token generated for ${userData.username}`)
                    res.json({ accessToken: accessToken })
                }).catch(error => {
                    res.sendStatus(500)
                })
        })
    }).catch(error => {
        res.sendStatus(404)
    })
})

const PORT = process.env.PORT
app.listen(PORT, () => {
  console.log(`QAuthify server running on port ${PORT}`)
})

/*https.createServer({
    key: privateKey,
    cert: certificate
}, app).listen(PORT, () => {
    console.log(`QAuthify server running on port ${PORT}`)
})*/