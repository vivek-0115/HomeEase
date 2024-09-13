#================== Importing Important Modules=========================#

from flask import Flask, render_template, redirect, url_for, request, flash, abort, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import base64
import os,io
import fitz
import datetime
from werkzeug.utils import secure_filename


#==================Initialising App Component===========================#

HomeEase = Flask(__name__)

#==================Confugaration App Component===========================#

HomeEase.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
HomeEase.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
HomeEase.config['SECRET_KEY'] = 'HomeEase'

db = SQLAlchemy()
db.init_app(HomeEase)
login_manager = LoginManager()
login_manager.init_app(HomeEase)

#==================End Of Confugaration App Component===========================#


#==================Databse Models===========================#

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref='role', lazy=True)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    
    # Relationships
    admin = db.relationship('Admin', backref='user', uselist=False, lazy=True)
    customer = db.relationship('Customer', backref='user', uselist=False, lazy=True)
    professional = db.relationship('Professional', backref='user', uselist=False, lazy=True)
    address = db.relationship('Address', backref='user', uselist=False, lazy=True)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fname = db.Column(db.String(20), nullable=False)
    lname = db.Column(db.String(20), nullable=True)
    picture = db.Column(db.LargeBinary, nullable=True)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fname = db.Column(db.String(20), nullable=False)
    lname = db.Column(db.String(20), nullable=True)
    phone_no = db.Column(db.String(15), nullable=False)
    picture = db.Column(db.LargeBinary, nullable=True)

class Professional(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fname = db.Column(db.String(20), nullable=False)
    lname = db.Column(db.String(20), nullable=True)
    phone_no = db.Column(db.String(15), nullable=False)
    service_type = db.Column(db.String(20), nullable=False)
    resume = db.Column(db.LargeBinary, nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    picture = db.Column(db.LargeBinary, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    city = db.Column(db.String(20), nullable=False)
    street = db.Column(db.String(50), nullable=False)
    zipcode = db.Column(db.String(10), nullable=False)

class ServiceAreaAssociation(db.Model):
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), primary_key=True)
    area_id = db.Column(db.Integer, db.ForeignKey('service_area.id'), primary_key=True)
    
class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    service_requests = db.relationship('ServiceRequest', backref='service', lazy=True)
    reviews = db.relationship('Review', backref='service', lazy=True)
    areas = db.relationship('ServiceArea', secondary='service_area_association', backref='services')

class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=True)
    date_of_request = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    date_of_completion = db.Column(db.DateTime, nullable=True)
    service_status = db.Column(db.String(20), default='requested', nullable=False)
    remarks = db.Column(db.Text, nullable=True)

class ServiceArea(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(50), nullable=True)
    city = db.Column(db.String(50), nullable=True)
    zipcode = db.Column(db.String(10), nullable=True)
    street = db.Column(db.String(100), nullable=False)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)
    remark = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)    
    
with HomeEase.app_context():
    db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.sqlite3')
    if not os.path.exists(db_path):
        db.create_all()
        if not Role.query.first():
            roles_to_create = ['admin', 'customer', 'professional']
            for role_name in roles_to_create:
                if not Role.query.filter_by(name=role_name).first():
                    new_role = Role(name=role_name)
                    db.session.add(new_role)
            db.session.commit()
            print("Three Main Roles Are Created")

            admin_role = Role.query.filter_by(name='admin').first()
            if admin_role and not User.query.filter_by(email='admin@mail.com').first():

                hashed_password = generate_password_hash('admin')
            
                admin_user = User(
                email='admin@mail.com',
                password=hashed_password,
                role_id=admin_role.id
                )
                db.session.add(admin_user)
                db.session.commit()
                print("Admin user created with email: admin@mail.com")

                admin_details = Admin(
                user_id=admin_user.id,
                fname='Vivek',
                lname='Raj'    
                )
                db.session.add(admin_details)
                db.session.commit()

#==================End Of Databse Models===========================#

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#==================Home Pages Control===========================#
@HomeEase.route("/home")
@HomeEase.route("/")
def home():
    return render_template('/Home/home.html')

@HomeEase.route("/home/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(email=username).first()

        if user:
            if check_password_hash(user.password, password):
                if not user.active:
                    flash('Your account is inactive. Please contact support.', 'warning')
                    return redirect(url_for('login'))

                login_user(user)
                role_name = user.role.name

                if role_name == 'admin':
                    return redirect(url_for('admin_home', id=user.id))
                elif role_name == 'customer':
                    return redirect(url_for('customer', id=user.id))
                elif role_name == 'professional':
                    return redirect(url_for('professional_home', id=user.id))

            else:
                flash('Incorrect Password!','error')
                return redirect(url_for('login'))
        else:
            flash('Incorrect Username(Email)!','warning')
            return redirect(url_for('login'))

    return render_template('/Home/home-login.html')
    
@HomeEase.route("/logout")
@login_required
def logout():       #Login and their logics
    logout_user()
    return redirect(url_for('home'))

@HomeEase.route("/home/join/customer_registration", methods=['GET', 'POST'])
def join_cust():
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')

        state = request.form.get('state')
        city = request.form.get('city')
        street = request.form.get('street')
        zipcode = request.form.get('zipcode')

        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_pass = request.form.get('confirm-password')

        if not User.query.filter_by(email=email).first():
            if password != confirm_pass:
                flash("Password doesn't match !", 'warning')
                return redirect(url_for('join_cust'))
            else:
                password = generate_password_hash(confirm_pass)
                role_id = Role.query.get(2)
                user = User(
                    email = email, password = password, role=role_id
                )
                db.session.add(user)
                db.session.commit()

                existing_user = User.query.filter_by(email=email).first()

                customer = Customer(
                    user_id=existing_user.id, fname=fname, lname=lname, phone_no=phone
                )
                db.session.add(customer)
                db.session.commit()

                address = Address(
                    user_id=existing_user.id, state=state, city=city, street=street, zipcode=zipcode
                )
                db.session.add(address)
                db.session.commit()

                flash('Registration Successfull','success')
                return redirect(url_for('login'))

        else:
            flash("Email Already Registered! Try to login", 'info')
            return redirect(url_for('join_cust'))

        
    return render_template('/Home/join-cust.html')

@HomeEase.route("/home/join/professional_registration", methods=['GET', 'POST'])
def join_prof():
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')

        state = request.form.get('state')
        city = request.form.get('city')
        street = request.form.get('street')
        zipcode = request.form.get('zipcode')

        service_type = request.form.get('services')
        resume = request.files['resume']
        experience = request.form.get('experience')

        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_pass = request.form.get('confirm-password')

        pdf_data = resume.read()
        pdf_document = fitz.open(stream=pdf_data, filetype="pdf")
        page_no = len(pdf_document)
        pdf_document.close()

        if not User.query.filter_by(email=email).first():
            if service_type != 'NoSelected':
                if page_no == 1:
                    if password == confirm_pass:
                        #Adding Data to the Database
                        password = generate_password_hash(confirm_pass)
                        role_id = Role.query.get(3)
                        user = User(
                            email = email, password = password, role=role_id
                        )
                        db.session.add(user)
                        db.session.commit()

                        existing_user = User.query.filter_by(email=email).first()

                        professional = Professional(
                            user_id=existing_user.id, fname=fname, lname=lname, phone_no=phone, resume=pdf_data,
                            experience = experience, service_type=service_type
                        )
                        db.session.add(professional)
                        db.session.commit()

                        address = Address(
                        user_id=existing_user.id, state=state, city=city, street=street, zipcode=zipcode
                        )
                        db.session.add(address)
                        db.session.commit()

                        flash('Registration Successfull','success')
                        return redirect(url_for('login'))
                    else:
                        flash("Password doesn't match !", 'warning')
                        return redirect(url_for('join_prof'))
                else:
                    flash('Please Select Single Page PDF.', 'warning')
                    return redirect(url_for('join_prof'))
            else:
                flash('Please Select Your Service Type.', 'warning')
                return redirect(url_for('join_prof'))
        else:
            flash("Email Already Registered! Try to login", 'info')
            return redirect(url_for('join_prof'))


    return render_template('/Home/join-prof.html')

@HomeEase.route("/home/about-us")
def about():
    return render_template('/Home/home-aboutus.html')
#==================End Of Home Pages Control===========================#

#==================Admin Control===========================#

@HomeEase.route('/HomeEase/admin/<int:id>/home')
@login_required
def admin_home(id):

    user_admin = User.query.filter_by(id=id).first_or_404()
    admin_detail = Admin.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if admin_detail.picture:
        picture_base64 = base64.b64encode(admin_detail.picture).decode('utf-8')

    adminData = {"admin":user_admin, "adminDetail":admin_detail, "picture":picture_base64, "mimetype":'image/png'}
    return render_template("/Admin/home.html", admin=adminData)

@HomeEase.route('/HomeEase/admin/<int:id>/profile')
@login_required
def admin_profile(id):

    user_admin = User.query.filter_by(id=id).first_or_404()
    admin_detail = Admin.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if admin_detail.picture:
        picture_base64 = base64.b64encode(admin_detail.picture).decode('utf-8')

    adminData = {"admin":user_admin, "adminDetail":admin_detail, "picture":picture_base64, "mimetype":'image/png'}
    return render_template("/Admin/profile.html", admin=adminData)

@HomeEase.route('/HomeEase/admin/<int:id>/change_password', methods=['GET', 'POST'])
@login_required
def admin_change_password(id):
    if request.method=="POST":
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        user = User.query.filter_by(id=id).first_or_404()

        if check_password_hash(user.password, old_password):
            user.password = generate_password_hash(new_password)
            db.session.add(user)
            db.session.commit()

            flash("Password Changed.", 'success')
        else:
            flash("Password doesn't match", 'error')
        return redirect(url_for('admin_profile',id=id))
    return abort(405)

@HomeEase.route('/HomeEase/admin/<int:id>/change_profile', methods=['GET', 'POST'])
@login_required
def admin_change_profile(id):
    if request.method=="POST":
        if 'photo' in request.files:
            photo = request.files['photo']
            admin = Admin.query.filter_by(user_id=id).first_or_404()

            admin.picture = photo.read()
            db.session.add(admin)
            db.session.commit()

        return redirect(url_for('admin_profile',id=id))
    return abort(405)

@HomeEase.route('/HomeEase/admin/<int:id>/update_information', methods=['GET', 'POST'])
@login_required
def admin_update_information(id):
    if request.method == "POST":
        fname = request.form.get('fname')
        lname = request.form.get('lname')

        admin = Admin.query.filter_by(user_id=id).first_or_404()

        admin.fname = fname
        admin.lname = lname

        db.session.add(admin)
        db.session.commit()
        
        flash('Information Updated','success')
        return redirect(url_for('admin_profile',id=id))
    else:
        abort(405)

@HomeEase.route('/HomeEase/admin/<int:id>/manage_users')
@login_required
def manage_users(id):
    user_admin = User.query.filter_by(id=id).first_or_404()
    admin_detail = Admin.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if admin_detail.picture:
        picture_base64 = base64.b64encode(admin_detail.picture).decode('utf-8')

    adminData = {"admin":user_admin, "adminDetail":admin_detail, "picture":picture_base64, "mimetype":'image/png'}

    un_verified = Professional.query.filter_by(is_verified=0).all()

    un_verified_list=[]
    for prof in un_verified:
        user = User.query.filter_by(id=prof.user_id).first_or_404()
        if user.active:
            adrs = Address.query.filter_by(user_id=prof.user_id).first_or_404()

            prof_dict={
            "id":user.id,"service_type":prof.service_type,
            "fname":prof.fname, "lname":prof.lname, "email":user.email,
            "phone":prof.phone_no, "state":adrs.state, "city":adrs.city,
            "street":adrs.street, "zipcode":adrs.zipcode,
            }
            un_verified_list.append(prof_dict)

    active_list = []
    for user in User.query.filter_by(active=1).all():
        if user.role.name=='professional':
            prof = Professional.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":prof.fname, "lname":prof.fname, "email":user.email, "user_type":user.role.name}
            active_list.append(userData)
        elif user.role.name == 'customer':
            cust = Customer.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":cust.fname, "lname":cust.fname, "email":user.email, "user_type":user.role.name}
            active_list.append(userData)

    block_list = []
    for user in User.query.filter_by(active=0).all():
        if user.role.name=='professional':
            prof = Professional.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":prof.fname, "lname":prof.fname, "email":user.email, "user_type":user.role.name}
            block_list.append(userData)
        elif user.role.name == 'customer':
            cust = Customer.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":cust.fname, "lname":cust.fname, "email":user.email, "user_type":user.role.name}
            block_list.append(userData)

    print("block",block_list)

    return render_template("/Admin/manage_users.html", admin=adminData, un_verified=un_verified_list, actives=active_list, blocks=block_list)

@HomeEase.route('/HomeEase/admin/<int:id>/view_resume/<int:prof_id>')
@login_required
def view_resume(id,prof_id):
    resume = Professional.query.filter_by(user_id=prof_id).first_or_404()
    if resume:
        return Response(
            io.BytesIO(resume.resume),
            mimetype='application/pdf',
            headers={'Content-Disposition': 'inline; filename=document.pdf'}
        )
    return 'Resume not found', 404

@HomeEase.route('/HomeEase/admin/<int:id>/verifying/<int:prof_id>')
@login_required
def verify_professional(id,prof_id):
    professional = Professional.query.filter_by(user_id=prof_id).first_or_404()
    professional.is_verified=1
    db.session.add(professional)
    db.session.commit()
    return redirect(url_for('manage_users',id=id))

@HomeEase.route('/HomeEase/admin/<int:id>/rejecting/<int:prof_id>')
@login_required
def reject_professional(id,prof_id):
    professional = User.query.filter_by(id=prof_id).first_or_404()
    professional.active=0
    db.session.add(professional)
    db.session.commit()
    return redirect(url_for('manage_users',id=id))

@HomeEase.route('/HomeEase/admin/<int:id>/blocking/<int:user_id>')
@login_required
def block_user(id,user_id):
    user = User.query.filter_by(id=user_id).first_or_404()
    user.active=0
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('manage_users',id=id))

@HomeEase.route('/HomeEase/admin/<int:id>/unblocking/<int:user_id>')
@login_required
def unblock_user(id,user_id):
    user = User.query.filter_by(id=user_id).first_or_404()
    user.active=1
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('manage_users',id=id))

@HomeEase.route('/HomeEase/admin/<int:id>/view_user/<int:user_id>')
@login_required
def view_user(id, user_id):
    user = User.query.filter_by(id=user_id).first_or_404()

    user_admin = User.query.filter_by(id=id).first_or_404()
    admin_detail = Admin.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if admin_detail.picture:
        picture_base64 = base64.b64encode(admin_detail.picture).decode('utf-8')

    adminData = {"admin":user_admin, "adminDetail":admin_detail, "picture":picture_base64, "mimetype":'image/png'}

    if user.role.name=='professional':
        prof = Professional.query.filter_by(user_id=user.id).first_or_404()
        adrs = Address.query.filter_by(user_id=user_id).first_or_404()

        picture_base64=''
        if prof.picture:
            picture_base64 = base64.b64encode(prof.picture).decode('utf-8')
        userData={"user":user, "userData":prof, "adrs":adrs, "picture":picture_base64, "mimetype":'image/png'}
        return render_template("/Admin/view_user.html",admin=adminData, user=userData)
    elif user.role.name == 'customer':
        cust = Customer.query.filter_by(user_id=user.id).first_or_404()
        adrs = Address.query.filter_by(user_id=user_id).first_or_404()

        picture_base64=''
        if cust.picture:
            picture_base64 = base64.b64encode(cust.picture).decode('utf-8')
        userData={"user":user, "userData":cust, "adrs":adrs, "picture":picture_base64, "mimetype":'image/png'}
        return render_template("/Admin/view_user.html",admin=adminData, user=userData)

@HomeEase.route('/HomeEase/admin/<int:id>/services')
@login_required
def services(id):
    user_admin = User.query.filter_by(id=id).first_or_404()
    admin_detail = Admin.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if admin_detail.picture:
        picture_base64 = base64.b64encode(admin_detail.picture).decode('utf-8')

    adminData = {"admin":user_admin, "adminDetail":admin_detail, "picture":picture_base64, "mimetype":'image/png'}
    return render_template('/Admin/services.html',admin=adminData)
#==================End Of Admin Control===========================#


#==================Professionals Control===========================#

@HomeEase.route('/HomeEase/professioinal/<int:id>/home')
@login_required
def professional_home(id):

    if current_user.id != id:
        return abort(403)

    user_prof = User.query.filter_by(id=id).first_or_404()
    professional = Professional.query.filter_by(user_id=id).first_or_404()
    adrs = Address.query.filter_by(user_id=id).first_or_404()

     # Convert binary image data to Base64
    picture_base64=''
    if professional.picture:
        picture_base64 = base64.b64encode(professional.picture).decode('utf-8')

    prof_data = {
        "id":user_prof.id,
        "fname":professional.fname, "lname":professional.lname, "email":user_prof.email,
        "phone":professional.phone_no, "state":adrs.state, "city":adrs.city,"experience":professional.experience,
        "street":adrs.street, "zipcode":adrs.zipcode, "is_verified":professional.is_verified,
        "picture":picture_base64, "mimetype":'image/png'
    }
    return render_template('/Professional/home.html', professional=prof_data)

@HomeEase.route('/HomeEase/professioinal/<int:id>/profile')
@login_required
def professional_profile(id):

    if current_user.id != id:
        return abort(403)
    
    professional = Professional.query.filter_by(user_id=id).first_or_404()

    if not professional.is_verified:
        return abort(403)

    user_prof = User.query.filter_by(id=id).first_or_404()
    adrs = Address.query.filter_by(user_id=id).first_or_404()

     # Convert binary image data to Base64
    picture_base64=''
    if professional.picture:
        picture_base64 = base64.b64encode(professional.picture).decode('utf-8')

    prof_data = {
        "id":user_prof.id,
        "fname":professional.fname, "lname":professional.lname, "email":user_prof.email,
        "phone":professional.phone_no, "state":adrs.state, "city":adrs.city,"experience":professional.experience,
        "street":adrs.street, "zipcode":adrs.zipcode, "is_verified":professional.is_verified,
        "picture":picture_base64, "mimetype":'image/png'
    }
    return render_template('/Professional/profile.html', data=prof_data)

@HomeEase.route('/HomeEase/professional/<int:id>/change_profile', methods=['GET', 'POST'])
@login_required
def professional_change_profile(id):
    if request.method=="POST":
        if 'photo' in request.files:
            photo = request.files['photo']
            professional = Professional.query.filter_by(user_id=id).first_or_404()

            professional.picture = photo.read()
            db.session.add(professional)
            db.session.commit()

        return redirect(url_for('professional_profile',id=id))
    return abort(405)

@HomeEase.route('/HomeEase/professional/<int:id>/change_password', methods=['GET', 'POST'])
def professional_change_password(id):
    if request.method=="POST":
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        user = User.query.filter_by(id=id).first_or_404()

        if check_password_hash(user.password, old_password):
            user.password = generate_password_hash(new_password)
            db.session.add(user)
            db.session.commit()

            flash("Password Changed.", 'success')
        else:
            flash("Password doesn't match", 'error')
        return redirect(url_for('professional_profile',id=id))
    return abort(405)

@HomeEase.route('/HomeEase/customer/<int:id>/update_information', methods=['GET', 'POST'])
def professional_update_information(id):
    if request.method == "POST":
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        state = request.form.get('state')

        city = request.form.get('city')
        street = request.form.get('street')
        zipcode = request.form.get('zipcode')
        phone = request.form.get('phone')

        professional = Professional.query.filter_by(user_id=id).first_or_404()
        address = Address.query.filter_by(user_id=id).first_or_404()

        professional.fname = fname
        professional.lname = lname
        professional.phone_no = phone

        address.city = city
        address.state = state
        address.street = street
        address.zipcode = zipcode

        db.session.add(professional)
        db.session.add(address)
        db.session.commit()

        flash('Information Updated','success')
        return redirect(url_for('professional_profile',id=id))
    else:
        abort(405)
    
#==================Endof Professionals Control===========================#


#==================Customers Control===========================#

@HomeEase.route('/HomeEase/customer/<int:id>')
@login_required
def customer(id):
    if current_user.id != id:
        return abort(403)

    user_cust = User.query.filter_by(id=id).first_or_404()
    customer = Customer.query.filter_by(user_id=id).first_or_404()
    adrs = Address.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if customer.picture:
        picture_base64 = base64.b64encode(customer.picture).decode('utf-8')

    cust_data = {
        "id":user_cust.id,
        "fname":customer.fname, "lname":customer.lname, "email":user_cust.email,
        "phone":customer.phone_no, "state":adrs.state, "city":adrs.city,
        "street":adrs.street, "zipcode":adrs.zipcode,
        "picture":picture_base64, "mimetype":'image/png'
    }
    return render_template('/Customer/profile.html', data=cust_data)

@HomeEase.route('/HomeEase/customer/<int:id>/change_profile', methods=['GET', 'POST'])
@login_required
def change_profile(id):
    if request.method=="POST":
        if 'photo' in request.files:
            photo = request.files['photo']
            customer = Customer.query.filter_by(user_id=id).first_or_404()

            customer.picture = photo.read()
            db.session.add(customer)
            db.session.commit()

        return redirect(url_for('customer',id=id))
    return abort(405)

@HomeEase.route('/HomeEase/customer/<int:id>/change_password', methods=['GET', 'POST'])
def change_password(id):
    if request.method=="POST":
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        user = User.query.filter_by(id=id).first_or_404()

        if check_password_hash(user.password, old_password):
            user.password = generate_password_hash(new_password)
            db.session.add(user)
            db.session.commit()

            flash("Password Changed.", 'success')
        else:
            flash("Password doesn't match", 'error')
        return redirect(url_for('customer',id=id))
    return abort(405)

@HomeEase.route('/HomeEase/customer/<int:id>/update_information', methods=['GET', 'POST'])
def update_information(id):
    if request.method == "POST":
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        state = request.form.get('state')

        city = request.form.get('city')
        street = request.form.get('street')
        zipcode = request.form.get('zipcode')
        phone = request.form.get('phone')

        customer = Customer.query.filter_by(user_id=id).first_or_404()
        address = Address.query.filter_by(user_id=id).first_or_404()

        customer.fname = fname
        customer.lname = lname
        customer.phone_no = phone

        address.city = city
        address.state = state
        address.street = street
        address.zipcode = zipcode

        db.session.add(customer)
        db.session.add(address)
        db.session.commit()

        flash('Information Updated','success')
        return redirect(url_for('customer',id=id))
    else:
        abort(405)

#==================Customers Control End===========================#

if __name__ == "__main__":
    HomeEase.run(debug=True, host='192.168.29.7', port=5000)