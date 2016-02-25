import os
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from flask import Flask, render_template, redirect, jsonify, flash, request, url_for
from flask_bootstrap import Bootstrap
from flask_login import login_user, logout_user, login_required, current_user, UserMixin, LoginManager
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import Form
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config["JSON_SORT_KEYS"] = True

bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    client_id = db.Column(db.String(256), unique=True, default=sha256(str(uuid4()).encode('UTF-8')).hexdigest())
    client_secret = db.Column(db.String(256), unique=True, default=sha256(str(uuid4()).encode('UTF-8')).hexdigest())
    redirect_uri = db.Column(db.String(128), default='http://localhost:5000/')
    code = db.Column(db.String(128), default=None)
    access_token = db.Column(db.String(128), default=None)
    refresh_token = db.Column(db.String(128), default=None)
    expire_time = db.Column(db.DateTime, default=None)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


@app.route('/oauth/authorize', methods=['GET'])
def authorize_form():
    response_type = request.args.get('response_type', None)
    client_id = request.args.get('client_id', None)
    state = request.args.get('state', None)

    if client_id is None:
        return render_template('fail.html', reason='require client_id.')

    u = User.query.filter_by(client_id=client_id).first()
    if u is None:
        return render_template('fail.html', reason='client_id is invalid.')

    if response_type is None:
        return redirect(u.redirect_uri + '?error=invalid_request' +
                        ('' if state is None else '&state=' + state), code=302)
    if response_type != 'code':
        return redirect(u.redirect_uri + '?error=unsupported_response_type' +
                        ('' if state is None else '&state=' + state), code=302)
    if current_user.is_authenticated:
        if str(u.client_id) == str(client_id):
            code = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
            u.code = str(code)
            db.session.add(u)
            return redirect(u.redirect_uri + '?code=' + code + ('' if state is None else '&state=' + state),
                            code=302)
        return redirect(u.redirect_uri + '?error=access_denied' + ('' if state is None else '&state=' + state),
                        code=302)
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/oauth/authorize', methods=['POST'])
def authorize():
    form = LoginForm()
    x = request.args.get('client_id', None)
    state = request.args.get('state', None)
    if x is None:
        return render_template('fail.html', reason='require client_id.')
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            if str(user.client_id) == str(x):
                code = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
                user.code = str(code)
                db.session.add(user)
                return redirect(user.redirect_uri + '?code=' + code + ('' if state is None else '&state=' + state),
                                code=302)
            return redirect(user.redirect_uri + '?error=access_denied' + ('' if state is None else '&state=' + state),
                            code=302)
        flash('Invalid email or password.')
    return render_template('login.html', form=form)


@app.route('/oauth/token', methods=['POST'])
def token():
    try:
        grant_type = request.args.get('grant_type', None)
        client_id = request.args.get('client_id', None)
        client_secret = request.args.get('client_secret', None)
    except KeyError:
        return jsonify({'error': 'invalid_request!!!'}), 400

    if client_id is None:
        return jsonify({'error': 'invalid_request'}), 400

    u = User.query.filter_by(client_id=client_id).first()

    if u is None:
        return jsonify({'error': 'invalid_client'}), 400

    if str(u.client_secret) != str(client_secret):
        return jsonify({'error': 'invalid_request'}), 400

    if grant_type == 'authorization_code':
        code = request.args.get('code', None)
        if code is None:
            return jsonify({'error': 'invalid_request'}), 400
        if str(u.code) != str(code):
            return jsonify({'error': 'invalid_grant'}), 400
        u.code = None
        db.session.add(u)
    elif grant_type == 'refresh_token':
        refresh_token = request.args.get('refresh_token', None)
        if refresh_token is None:
            return jsonify({'error': 'invalid_request'}), 400
        if str(u.refresh_token) != str(refresh_token):
            return jsonify({'error': 'invalid_grant'}), 400
        u.refresh_token = None
        db.session.add(u)
    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400
    access_token = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    expire_time = datetime.now() + timedelta(hours=1)
    refresh_token = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    u.access_token = access_token
    u.expire_time = expire_time
    u.refresh_token = refresh_token
    db.session.add(u)
    db.session.commit()
    return jsonify({
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': 3600,
        'refresh_token': refresh_token}), 200, {
               'Cache-Control': 'no-store',
               'Pragma': 'no-cache',
           }



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('index'))
        flash('Invalid email or password.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        flash('You can now login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


######################################## DB operations

class Marks(db.Model):
    __tablename__ = 'marks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    car_models = db.relationship('Car_model', backref='mark', lazy='dynamic')

    def __repr__(self):
        return '<Marks %r>' % self.name

    def to_json_for_car_models(self):
        num = Car_model.query.filter_by(mark_id=self.id).count()
        json_mark = {
            'mark_id': self.id,
            'mark_name': self.name,
            'number_of_models': num,
        }
        return json_mark

    def to_json_for_marks(self):
        car_models = Car_model.query.filter_by(mark_id=self.id).all()
        num = Car_model.query.filter_by(mark_id=self.id).count()
        json_mark = {
            'mark_id': self.id,
            'mark_name': self.name,
            'number_of_models': num,
            'car_models': [car_model.to_json_for_marks() for car_model in car_models],
        }
        return json_mark


class Car_model(db.Model):
    __tablename__ = 'car_models'
    id = db.Column(db.Integer, primary_key=True)
    car_model = db.Column(db.String(1024), unique=False, index=True)
    mark_id = db.Column(db.Integer, db.ForeignKey('marks.id'))
    time = db.Column(db.Integer, index=True, default=datetime.utcnow())

    def __repr__(self):
        return '<Car_model %r>' % self.car_model

    def to_json_for_car_models(self):
        r = Marks.query.filter_by(id=self.mark_id).first()
        json_user = {
            'car_model_id': self.id,
            'car_model': self.car_model,
            'mark_id': self.mark_id,
            'mark_name': r.name,
        }
        return json_user

    def to_json_for_marks(self):
        json_user = {
            'car_model': self.car_model,
            'car_model_id': self.id,
        }
        return json_user

    @staticmethod
    def from_json(json_post):
        car_model = json_post.get('car_model')
        mark = json_post.get('mark')
        if (car_model is None or car_model == '') or (mark is None or mark == ''):
            return Car_model(car_model=None)
        r = Marks.query.filter_by(name=mark).first()
        if r is None:
            r = Marks(name=mark)
            return Car_model(car_model=car_model, mark=r)
        else:
            return Car_model(car_model=car_model, mark_id=r.id)


class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')


class PostNewCarModel(Form):
    car_model = TextAreaField('Model', validators=[Length(1, 1024)])
    mark = StringField('Mark', validators=[Length(1, 128)])
    submit = SubmitField('Submit')


class RedirectForm(Form):
    redirect_uri = StringField('Redirect URL', validators=[Length(5, 128)])
    submit = SubmitField('Submit')


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/status')
def state():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if (u is None or u.expire_time < datetime.now()) and not current_user.is_authenticated:
        return jsonify({
            'status': 'stranger'
        })
    u = current_user
    return jsonify({
        'status': 'registered user',
        'email': u.email,
        'username': u.username
    })


@app.route('/me')
def me():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
         return '', 403
    if (u is None or u.expire_time < datetime.now()) and not current_user.is_authenticated:
        return jsonify({
            'you are': 'stranger'
        })
    return jsonify({
         'email': u.email,
        'you are': u.username
    })


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    form = RedirectForm()
    if current_user.is_authenticated:
        return render_template('profile.html', form=form)
    else:
        return '', 403


@app.route('/', methods=['GET', 'POST'])
def index():
    form = PostNewCarModel()
    if form.validate_on_submit():
        s = form.car_model.data
        n = form.mark.data
        car_model = Car_model.query.filter_by(car_model=s).first()
        if car_model is None:
            mark = Marks.query.filter_by(name=n).first()
            if mark is None:
                mark = Marks(name=n)
                car_model = Car_model(car_model=s, mark=mark)
            else:
                car_model = Car_model(car_model=s, mark_id=mark.id)
            db.session.add(car_model)
        else:
            flash('The same car has already added')
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    pagination = Car_model.query.order_by(Car_model.time.desc()).paginate(page, per_page=10, error_out=True)
    car_models = pagination.items
    marks = Marks.query.all()
    return render_template('index.html', form=form, car_models=car_models, marks=marks, pagination=pagination)


@app.route('/car_models/', methods=['GET'])
def get_car_models():
    # access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    # u = User.query.filter_by(access_token=access_token).first()
    # if u is None or u.expire_time < datetime.now():
    #     return '', 403
    page = request.args.get('page', 1, type=int)
    pagination = Car_model.query.paginate(page, per_page=10, error_out=True)
    car_models = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('get_car_models', page=page - 1, _external=True)
    next = None
    if pagination.has_next:
        next = url_for('get_car_models', page=page + 1, _external=True)
    items_on_page = 0
    for item in pagination.items:
        items_on_page += 1
    return jsonify({
        'items_on_page': items_on_page,
        'total_items': pagination.total,
        'page_number': pagination.page,
        'total_pages': pagination.pages,
        'prev': prev,
        'next': next,
        'car_models': [car_model.to_json_for_car_models() for car_model in car_models]
    })


@app.route('/marks/', methods=['GET'])
def get_marks():
    # access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    # u = User.query.filter_by(access_token=access_token).first()
    # if u is None or u.expire_time < datetime.now():
    #     return '', 403
    page = request.args.get('page', 1, type=int)
    pagination = Marks.query.paginate(page, per_page=10, error_out=True)
    marks = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('get_marks', page=page - 1, _external=True)
    next = None
    if pagination.has_next:
        next = url_for('get_marks', page=page + 1, _external=True)
    items_on_page = 0
    for item in pagination.items:
        items_on_page += 1
    return jsonify({
        'items_on_page': items_on_page,
        'total_items': pagination.total,
        'page_number': pagination.page,
        'total_pages': pagination.pages,
        'prev': prev,
        'next': next,
        'marks': [mark.to_json_for_car_models() for mark in marks],
    })


@app.route('/marks/<int:id>')
def get_mark(id):
    # access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    # u = User.query.filter_by(access_token=access_token).first()
    # if u is None or u.expire_time < datetime.now():
    #     return '', 403
    post = Marks.query.get_or_404(id)
    return jsonify(post.to_json_for_marks())


@app.route('/car_models/<int:id>', methods=['GET'])
def get_car_model(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    car_model = Car_model.query.get_or_404(id)
    return jsonify(car_model.to_json_for_car_models())


@app.route('/car_models/', methods=['POST'])
def new_car_model():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    car_model = Car_model.from_json(request.json)
    find_users = Car_model.query.filter_by(car_model=car_model.car_model).first()
    if find_users is None:
        if car_model.car_model is None:
            return jsonify({'error': 'Name or Mark are lost'}), 400
        db.session.add(car_model)
        db.session.commit()
        return jsonify(car_model.to_json_for_car_models()), 201
    else:
        return jsonify({'error': 'Same car exists'}), 409


@app.route('/car_models/<int:id>', methods=['PUT'])
def edit_car_model(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    car_model = Car_model.query.get_or_404(id)
    car_model.car_model = request.json.get('car_model', car_model.car_model)
    car_models = Car_model.query.filter_by(car_model=car_model.car_model).first()
    if car_models is None and (car_model.car_model != '' and car_model.car_model is not None):
        db.session.add(car_model)
        return jsonify(car_model.to_json_for_car_models())
    return jsonify({'error': 'Same car model exists'}), 409


@app.route('/marks/<int:id>', methods=['PUT'])
def edit_mark(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    mark = Marks.query.get_or_404(id)
    mark.name = request.json.get('mark', mark.name)
    marks = Marks.query.filter_by(name=mark.name).first()
    if marks is None and (mark.name != '' and mark.name is not None):
        db.session.add(mark)
        return jsonify(mark.to_json_for_car_models())
    else:
        return jsonify({'error': 'Same mark exists'}), 409


@app.route('/car_models/<int:id>', methods=['DELETE'])
def delete_car_model(id):
    # access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    # u = User.query.filter_by(access_token=access_token).first()
    # if u is None or u.expire_time < datetime.now():
    #     return '', 403
    car_model = Car_model.query.get_or_404(id)
    if car_model is None:
        return '', 404
    else:

        rr = Marks.query.filter_by(id=car_model.mark_id).first()
        db.session.delete(car_model)
        db.session.commit()
        car_model = Car_model.query.filter_by(mark_id=rr.id).first()
        if car_model is None:
            db.session.delete(rr)
            db.session.commit()
        return '', 410


@app.route('/marks/<int:id>', methods=['DELETE'])
def delete_mark(id):
    # access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    # u = User.query.filter_by(access_token=access_token).first()
    # if u is None or u.expire_time < datetime.now():
    #     return '', 403
    mark = Marks.query.get_or_404(id)
    if mark is None:
        return '', 404
    else:
        q = Car_model.query.filter_by(mark_id=mark.id).first()
        while q is not None:
            db.session.delete(q)
            db.session.commit()
            q = Car_model.query.filter_by(mark_id=mark.id).first()
        db.session.delete(mark)
        db.session.commit()
        return '', 410


if __name__ == '__main__':
    app.run()

