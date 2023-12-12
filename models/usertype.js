const mongoose = require('mongoose')

mongoose.set('strictQuery',false)

const url = `${process.env.MONGODB_URI}`

mongoose
  .connect(url, {ssl: true}) //under no circumstances should ssl communication with mongodb be disabled
  .then(() => {
    console.log('connected to MongoDB')
  })
  .catch((error) => {
    console.log('error connecting to MongoDB: ', error.message)
  })

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  usernameLow: {
    type: String,
    required: true
  },
  hashId: { //never modify this property as good practice
    type: String,
    required: false
  },
  hashPassword: {
    type: String,
    required: true
  },
  refreshTokens: [{
    token: String,
    creationDate: Number,
    lastUsageDate: Number,
    lastIp: String,
  }]
})

userSchema.set('toJSON', {
  transform: (document, returnedObject) => {
    returnedObject.userId = returnedObject._id.toString()
    delete returnedObject._id
    delete returnedObject.__v
  }
})

module.exports = mongoose.model('User', userSchema)