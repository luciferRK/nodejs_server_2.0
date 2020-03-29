const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

var userSchema = new mongoose.Schema({
    fullName:{
        type:String,
        required:'Full name cant be empty'
    },
    email:{
        type:String,
        required:'Email cant be empty',
        unique:true
    },
    password:{
        type:String,
        required:'Password cant be empty',
        minlength:[4,'Password is too short'],
    },
    saltSecret:String
});



userSchema.pre('save',function(next){
    bcrypt.genSalt(10,(err,salt)=>{
        bcrypt.hash(this.password,salt,(err,hash)=>{
            this.password = hash;
            this.saltSecret = salt;
            next();
        });
    });
});

userSchema.methods.verifyPassword = function(password){
    return bcrypt.compareSync(password,this.password);
};

userSchema.methods.generateJwt = function(){
    return jwt.sign({_id:this._id},
        process.env.JWT_SECRET,
        {
            algorithm: 'HS256',
            expiresIn: process.env.JWT_EXP
        });
}

mongoose.model('User',userSchema);