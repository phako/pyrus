from flask import Flask, redirect
from flask import render_template, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import mysql
from flask_sqlalchemy import orm;
from flask import current_app, request, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
     login_required, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, BooleanField, IntegerField, SelectField
from flask_principal import Principal, Identity, AnonymousIdentity, \
     identity_changed
import crypt

app = Flask(__name__)
app.config.from_envvar('PYRUS_SETTINGS')
db = SQLAlchemy(app)

class Domain(db.Model):
    domain_name = db.Column(db.String(255), primary_key=True, nullable=False)
    prefix = db.Column(db.String(50), unique=True, nullable=False)
    maxaccounts = db.Column(mysql.INTEGER(11), nullable=False, default=20)
    quota = db.Column(mysql.INTEGER(10), nullable=False, default=20000)
    transport = db.Column(db.String(255), nullable=False, default='cyrus')
    backupmx = db.Column(mysql.TINYINT(1), nullable=False, default='0')
    freenames = db.Column(mysql.ENUM('YES', 'NO'), nullable=False, default='NO')
    freeaddress = db.Column(mysql.ENUM('YES', 'NO'), nullable=False, default='NO')

class AdminUser(UserMixin, db.Model):
    __tablename__ = 'adminuser'
    username = db.Column(db.String(50), primary_key=True, nullable=False)
    id = orm.synonym('username')
    password = db.Column(db.String(50), nullable=False)
    type = db.Column(mysql.INTEGER(11), nullable=False, default=0)

Principal(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    return AdminUser.query.get(id)

class LoginForm(FlaskForm):
    email = StringField(label='Username')
    password = PasswordField()
    submit = SubmitField('Sign In')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # A hypothetical login form that uses Flask-WTF
    form = LoginForm()

    # Validate form input
    if form.validate_on_submit():
        # Retrieve the user from the hypothetical datastore
        user = AdminUser.query.filter_by(username=form.email.data).first()

        # Compare passwords (use password hashing production)
        if user.password == crypt.crypt(form.password.data, user.password):
            # Keep the user info in the session using Flask-Login
            login_user(user)

            # Tell Flask-Principal the identity changed
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.username))

            return redirect(request.args.get('next') or '/')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    # Remove the user information from the session
    logout_user()

    # Remove session keys set by Flask-Principal
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    # Tell Flask-Principal the user is anonymous
    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())

    return redirect(request.args.get('next') or '/')

@app.route('/')
@app.route('/domains')
@login_required
def show_domains():
    return render_template('domains.html',
                           user=current_user,
                           domains=Domain.query.order_by(Domain.domain_name.asc()).all())

class DomainForm(FlaskForm):
    domainname = StringField()
    prefix = StringField()
    allow_free_names = BooleanField()
    allow_free_mail_addresses = BooleanField()
    maximum_accounts = IntegerField()
    default_quota = IntegerField()
    submit = SubmitField('Update')

    def _to_enum(self, bool):
        if bool:
            return 'YES'

        return 'NO'

    def _from_enum(self, enum):
        return enum == 'YES';

    def fill(self, domain):
        self.domainname.data = domain.domain_name
        self.prefix.data = domain.prefix
        self.allow_free_names.data = self._from_enum(domain.freenames)
        self.allow_free_mail_addresses.data = self._from_enum(domain.freeaddress)
        self.maximum_accounts.data = domain.maxaccounts
        self.default_quota.data = domain.quota

    def pop(self, domain):
        domain.domain_name = self.domainname.data
        domain.prefix = self.prefix.data;
        domain.freenames = self._to_enum(self.allow_free_names.data)
        domain.freeaddress = self._to_enum(self.allow_free_mail_addresses.data)
        domain.maxaccounts = self.maximum_accounts.data
        domain.quota = self.default_quota.data


@app.route('/domain/edit/<string:domain_name>', methods=['GET', 'POST'])
@login_required
def edit_domain(domain_name):
    session['domain'] = domain_name
    domain = Domain.query.get(domain_name)
    form = DomainForm()

    if form.validate_on_submit():
        form.pop(domain)
        db.session.commit()
        flash('Successfully modified {0}'.format(domain_name))
        return redirect('/domains')

    form.fill(domain)
    return render_template("edit-domain.html", form=form, user=current_user)


class AddDomainForm(DomainForm):
    standard_mailbox = StringField()
    transport = SelectField("Foo", choices=[('cyrus', 'cyrus'), ('lmtp', 'lmtp'),
                                            ('smtp','smtp'), ('uucp', 'uucp')])
    parameters = StringField()

    def fill(self, domain):
        pass

    def pop(self, domain):
        DomainForm.pop(self, domain)
        domain.transport = '{0}:{1}'.format(self.transport.data, self.parameters.data)


@app.route('/domain/add', methods=['GET', 'POST'])
@login_required
def add_domain():
    form = AddDomainForm()
    if form.validate_on_submit():
        domain = Domain()
        form.pop(domain)
        db.session.add(domain)
        db.session.commit()
        flash('Successfully created domain {0}'.format(form.domainname.data))

        return redirect('/domains')

    return render_template("add-domain.html", form=form, user=current_user)


@app.route('/domain/delete/<string:domain_name>', methods=['GET', 'POST'])
@login_required
def delete_domain(domain_name):
    return 'Hello World'

@app.route('/users')
@login_required
def adminusers():
    return 'Admin users!'


@app.route('/domain/accounts')
@login_required
def accounts():
    return 'Accounts for {0}'.session['domains']
