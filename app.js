var bodyParser = require('body-parser');
var express = require('express');
var mongoose = require('mongoose');
mongoose.Promise = global.Promise;
var sessions = require('client-sessions');
var bcrypt = require('bcryptjs');
var csurf = require('csurf');


var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

var User = mongoose.model('User', new Schema({
	id: ObjectId,
	firstName: String,
	lastName: String,
	email: {type: String, unique: true},
	password: String
}));


var app = express();
app.set('view engine', 'jade');
app.locals.pretty = true;

// connect to mongodb
mongoose.connect('mongodb://localhost/newauth')




//middleware
app.use(bodyParser.urlencoded({extended: true}));

app.use(sessions({
	cookieName: 'session',
	secret: 'eriwqygwpfhqvfdhjslburifhlruhwf132r2jfh',
	duration: 30 * 60 * 1000,
	activeDuration: 5 * 60 * 1000
}));

app.use(csurf());

app.use(function(req, res, next){
	if(req.session && req.session.user){
		User.findOne({email: req.session.user.email}, function(err, user){
			if(user){
				req.user = user;
				delete req.user.password;
				req.session.user = req.user;
				res.locals.user = req.user;
			}
			next();
		});
	} else {
		next();
	}
});

function requireLogin(req, res, next){
	if(!req.user){
		res.redirect('/login');
	} else {
		next();
	}
};

app.get('/', function(req, res){
	res.render('index.jade');
});

app.get('/register', function(req, res){
	res.render('register.jade', {csrfToken: req.csrfToken() });
});

app.post('/register', function(req, res){
	var hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));

	var user = new User({
		firstName: req.body.firstName,
		lastName: req.body.lastName,
		email: req.body.email,
		password: hash
	});
	user.save(function(err){
		if(err){
			var error = 'Something bad happend. Try again';
			if(err.code === 11000){
				error = 'That email is taken, try another';
			}
			res.render('register.jade', {error: error});
		} else {
			req.session.user = user;
			res.redirect('/dashboard');
		}
	})
});

app.get('/login', function(req, res){
	res.render('login.jade');
});

app.post('/login', function(req, res){
	User.findOne({email: req.body.email}, function(err, user){
		if(!user){
			res.render('login.jade', {error: 'Not valid password or email'});
		} else {
			if(bcrypt.compareSync(req.body.password, user.password)){
				req.session.user = user; 
				res.redirect('/dashboard');
			} else {
				res.render('login.jade', {error: 'Not valid password or email'});
			}
		}
	});
});

app.get('/dashboard', requireLogin, function(req, res){
	res.render('dashboard.jade');
});

app.get('/logout', function(req, res){
	req.session.reset();
	res.redirect('/');
});

app.listen(3000);