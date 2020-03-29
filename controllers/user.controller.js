const mongoose = require('mongoose');
const passport = require('passport');
const _ = require('lodash');

const User = mongoose.model('User');

module.exports.register = (req,res,next)=>{
    var user = new User();
    user.fullName = req.body.fullName;
    user.email = req.body.email;
    user.password = req.body.password;
    user.save((err,doc)=>{
        if(!err)
            res.send(doc);
        else   
            if (err.code==11000)
                res.status(422).send(['Duplicate Email found']);
            else    
                return next(err);
    });
}

// module.exports.getData(s) = (req,res,next)=>{
//     User.findOne({email:s},
//       (err,us) => {
//         if(!us){
//             return res.status(404).json({message:"User record not found"});
//         }
//         else{
//           return res.status(200).json({user:[us.fullName,us.email,us.password,us.saltSecret]});
//         }
//       }  
//     );
// };

module.exports.authenticate = (req,res,next) => {
    passport.authenticate('local',(err,user,info) =>{   
        if (err) return res.status(400).json(err);
        else if (user) return res.status(200).json({"token":user.generateJwt()});
        else return res.status(404).json(info);
    })(req,res);
}

module.exports.Profile = (req,res,next) => {
    User.findOne({_id:req._id},
        (err,user) =>{
            if(!user)
                return res.status(404).json({status:false,message:"User not found"});
            else{
                return res.status(200).json({status:true,user:_.pick(user,['fullName','email'])});
            }
        }    
    );
}