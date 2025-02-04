#================== Importing Important Modules=========================#

from flask import Flask, render_template, redirect, url_for, request, flash, abort, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import func
import base64
import os,io
import fitz



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
    created_at = db.Column(db.DateTime, default=datetime.now())
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
    created_at = db.Column(db.DateTime, default=datetime.now())
    rating = db.Column(db.Numeric(3,1), default=0)
    review_count = db.Column(db.Integer, default=0)

    service_requests = db.relationship('ServiceRequest', backref='service', lazy=True)
    reviews = db.relationship('Review', backref='service', lazy=True)
    areas = db.relationship('ServiceArea', secondary='service_area_association', backref='services')

class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=True)
    date_of_request = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    date_of_completion = db.Column(db.DateTime, nullable=True)
    service_status = db.Column(db.String(20), default='requested', nullable=False)
    remarks = db.Column(db.Text, nullable=True)

class RejectedService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=False)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_request.id'), nullable=False)
    date_of_rejection = db.Column(db.DateTime, default=datetime.now(), nullable=False)

class ServiceArea(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(50), nullable=True)
    city = db.Column(db.String(50), nullable=True)
    zipcode = db.Column(db.String(10), nullable=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('service_request.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)
    remark = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now())    
    
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
            if admin_role and not User.query.filter_by(email='admin@gmail.com').first():

                hashed_password = generate_password_hash('vivek')
            
                admin_user = User(
                email='admin@gmail.com',
                password=hashed_password,
                role_id=admin_role.id
                )
                db.session.add(admin_user)
                db.session.commit()
                print("Admin user created with email: admin@gmail.com")

                admin_details = Admin(
                user_id=admin_user.id,
                fname='Vivek',
                lname='Raj'    
                )
                db.session.add(admin_details)
                db.session.commit()
HomeEase.app_context().push()
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
                    return redirect(url_for('customer_home', id=user.id))
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
        fname = request.form.get('fname').strip()
        lname = request.form.get('lname').strip()
        email = request.form.get('email').strip()

        state = request.form.get('state').strip().lower()
        city = request.form.get('city').strip().lower()
        street = request.form.get('street').strip().lower()
        zipcode = request.form.get('zipcode').strip()

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
        fname = request.form.get('fname').strip()
        lname = request.form.get('lname').strip()
        email = request.form.get('email').strip()

        state = request.form.get('state').strip().lower()
        city = request.form.get('city').strip().lower()
        street = request.form.get('street').strip().lower()
        zipcode = request.form.get('zipcode').strip()

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

def get_admin(id):
    user_admin = User.query.filter_by(id=id).first_or_404()
    admin_detail = Admin.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if admin_detail.picture:
        picture_base64 = base64.b64encode(admin_detail.picture).decode('utf-8')

    adminData = {"admin":user_admin, "adminDetail":admin_detail, "picture":picture_base64, "mimetype":'image/png'}
    return adminData

@HomeEase.route('/HomeEase/admin/<int:id>/home')
@login_required
def admin_home(id):

    all_users=User.query.all()
    blocked_users=User.query.filter_by(active=0).all()

    all_cust=User.query.filter_by(role_id=2).all()
    blocked_cust=User.query.filter_by(role_id=2,active=0).all()

    all_prof=User.query.filter_by(role_id=3).all()
    blocked_prof=User.query.filter_by(role_id=3,active=0).all()

    all_service=Service.query.all()

    cleaning=Service.query.filter_by(category="cleaning").all()
    gardening=Service.query.filter_by(category="gardening").all()
    plumbing=Service.query.filter_by(category="plumbing").all()
    carpentry=Service.query.filter_by(category="carpentry").all()
    electrical=Service.query.filter_by(category="electrical").all()
    all_req=ServiceRequest.query.all()
    reviews=Review.query.all()

    infor={
        "Users":{
            "total":{
                "user":len(all_users)-1,
                "block":len(blocked_users)
            },
            "customer":{
                "user":len(all_cust),
                "block":len(blocked_cust)
            },
            "professional":{
                "user":len(all_prof),
                "block":len(blocked_prof)
            }
        },
        "Services":{
            "total":len(all_service),
            "electrical":len(electrical),
            "carpentry":len(carpentry),
            "cleaning":len(cleaning),
            "gardening":len(gardening),
            "plumbing":len(plumbing)
        },
        "Requests":{
            "total":len(all_req),
            "requested":len([req for req in all_req if req.service_status=='requested']),
            "closed":len([req for req in all_req if req.service_status=='closed']),
            "accepted":len([req for req in all_req if req.service_status=='accepted']),
        },
        "Reviews":{
            "total":len(reviews),
            "unremark":len([review for review in reviews if not review.remark])
        }
    }
    return render_template("/Admin/home.html", admin=get_admin(id), infor=infor)

@HomeEase.route('/HomeEase/admin/<int:id>/search', methods=['GET', 'POST'])
@login_required
def admin_search(id):
    if request.method=="POST":
        search_by=request.form.get('search_by')
        search_name=request.form.get('search_name').strip().lower()

        if search_by=='professional':
            result=[]
            all_prof=Professional.query.all()
            for prof in all_prof:
                fname=prof.fname.lower()
                lname=prof.lname.lower()
                if search_name in fname or search_name in lname or search_name==fname or search_name==lname:
                    user=User.query.filter_by(id=prof.user_id).first_or_404()
                    result.append((user,prof))
            return render_template("/Admin/search.html", admin=get_admin(id), actives=result, msg='professional')

        elif search_by=='customer':
            result=[]
            all_cust=Customer.query.all()
            for cust in all_cust:
                fname=cust.fname.lower()
                lname=cust.lname.lower()
                if search_name in fname or search_name in lname or search_name==fname or search_name==lname:
                    user=User.query.filter_by(id=cust.user_id).first_or_404()
                    result.append((user,cust))
            return render_template("/Admin/search.html", admin=get_admin(id), actives=result, msg='customer')
        elif search_by=='service':
            result=[]
            all_srvs=Service.query.all()
            for srvs in all_srvs:
                name=srvs.name.lower()
                if search_name in name or search_name==name:
                    result.append(srvs)
            return render_template("/Admin/search.html", admin=get_admin(id), actives=result, msg='service')

    return render_template("/Admin/search.html", admin=get_admin(id), actives='')

@HomeEase.route('/HomeEase/admin/<int:id>/profile')
@login_required
def admin_profile(id):
    return render_template("/Admin/profile.html", admin=get_admin(id))

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
            userData={"id":user.id, "fname":prof.fname, "lname":prof.lname, "email":user.email, "user_type":user.role.name}
            active_list.append(userData)
        elif user.role.name == 'customer':
            cust = Customer.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":cust.fname, "lname":cust.lname, "email":user.email, "user_type":user.role.name}
            active_list.append(userData)

    block_list = []
    for user in User.query.filter_by(active=0).all():
        if user.role.name=='professional':
            prof = Professional.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":prof.fname, "lname":prof.lname, "email":user.email, "user_type":user.role.name}
            block_list.append(userData)
        elif user.role.name == 'customer':
            cust = Customer.query.filter_by(user_id=user.id).first_or_404()
            userData={"id":user.id, "fname":cust.fname, "lname":cust.lname, "email":user.email, "user_type":user.role.name}
            block_list.append(userData)

    return render_template("/Admin/manage_users.html", admin=get_admin(id), un_verified=un_verified_list, actives=active_list, blocks=block_list)

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

    if user.role.name=='professional':
        prof = Professional.query.filter_by(user_id=user.id).first_or_404()
        adrs = Address.query.filter_by(user_id=user_id).first_or_404()

        picture_base64=''
        if prof.picture:
            picture_base64 = base64.b64encode(prof.picture).decode('utf-8')
        userData={"user":user, "userData":prof, "adrs":adrs, "picture":picture_base64, "mimetype":'image/png'}
        return render_template("/Admin/view_user.html",admin=get_admin(id), user=userData)
    elif user.role.name == 'customer':
        cust = Customer.query.filter_by(user_id=user.id).first_or_404()
        adrs = Address.query.filter_by(user_id=user_id).first_or_404()

        picture_base64=''
        if cust.picture:
            picture_base64 = base64.b64encode(cust.picture).decode('utf-8')
        userData={"user":user, "userData":cust, "adrs":adrs, "picture":picture_base64, "mimetype":'image/png'}
        return render_template("/Admin/view_user.html",admin=get_admin(id), user=userData)

@HomeEase.route('/HomeEase/admin/<int:id>/services')
@login_required
def services(id):
    services = Service.query.all()

    admin_requests_data=[]
    admin_requests = ServiceRequest.query.all()

    for req in admin_requests:
        cust = Customer.query.filter_by(id=req.customer_id).first_or_404()
        srvs = Service.query.filter_by(id = req.service_id).first_or_404()
        reviewed = Review.query.filter_by(request_id=req.id).first()

        if req.professional_id:
            prof = Professional.query.filter_by(id = req.professional_id).first_or_404()
            admin_requests_data.append((req,srvs,prof,cust,reviewed))
        else:
            admin_requests_data.append((req,srvs,'',cust,reviewed))

    return render_template('/Admin/services.html',admin=get_admin(id), services=services, requests=admin_requests_data)

@HomeEase.route('/HomeEase/admin/<int:id>/create_services', methods=['GET', 'POST'])
@login_required
def create_service(id):
    if request.method == 'POST':
        name = request.form.get('name')
        service = request.form.get('service')
        description = request.form.get('description')
        price = request.form.get('price')
        duration = request.form.get('duration')

        state = request.form.get('state').lower()
        city = request.form.get('city').lower()
        zipcode = request.form.get('zipcode').lower()

        if service:
            exist_service = Service.query.filter_by( name=name, category=service, description=description,
                                        price=price,duration=duration).first()
            if not exist_service:
                newService = Service(
                    name=name, category=service, description=description,price=price,
                    duration=duration, status='active'
                    )
                db.session.add(newService)
                db.session.commit()

            get_area = ServiceArea.query.filter_by(state=state, city=city, zipcode=zipcode).first()
            if not get_area:
                area = ServiceArea(state=state, city=city, zipcode=zipcode)
                db.session.add(area)
                db.session.commit()
            
            exist_area = ServiceArea.query.filter_by(state=state, city=city, zipcode=zipcode).first()
            exist_service = Service.query.filter_by( name=name, category=service, description=description,
            price=price,duration=duration).first()

            service_area = ServiceAreaAssociation(service_id=exist_service.id,
                                                        area_id=exist_area.id)
            db.session.add(service_area)
            db.session.commit()
            
        else:
            flash('Please Selelct Service type.','warning')
            return redirect(url_for('create_service',id=id))
        flash('Service Created.','success')
        return redirect(url_for('services',id=id))
    return render_template('/Admin/create_service.html',admin=get_admin(id), msg='create')

@HomeEase.route('/HomeEase/admin/<int:id>/edit_service/<int:srvs_id>', methods=['GET', 'POST'])
@login_required
def edit_service(id, srvs_id):
    service = Service.query.filter_by(id = srvs_id).first_or_404()
    area = ServiceAreaAssociation.query.filter_by(service_id = service.id).first_or_404()
    area_id = area.area_id
    area = ServiceArea.query.filter_by(id = area_id).first_or_404()
    service_area = ServiceAreaAssociation.query.filter_by(service_id=srvs_id).first_or_404()
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('service')
        description = request.form.get('description')
        price = request.form.get('price')
        duration = request.form.get('duration')

        state = request.form.get('state').lower()
        city = request.form.get('city').lower()
        zipcode = request.form.get('zipcode').lower()

        service.name = name
        service.category = category
        service.description = description
        service.price = price
        service.duration = duration

        db.session.add(service)
        db.session.commit()

        get_area = ServiceArea.query.filter_by(state=state, city=city, zipcode=zipcode).first()
        if not get_area:
            area = ServiceArea(state=state, city=city, zipcode=zipcode)
            db.session.add(area)
            db.session.commit()
        
        exist_area = ServiceArea.query.filter_by(state=state, city=city, zipcode=zipcode).first()
        service_area.area_id = exist_area.id

        db.session.add(service_area)
        db.session.commit()

        return redirect(url_for('services',id=id))

    return render_template('/Admin/create_service.html',admin=get_admin(id), services=services,
    service=service,area=area, msg='edit')

@HomeEase.route('/HomeEase/admin/<int:id>/delete_service/<int:srvs_id>', methods=['GET', 'POST'])
@login_required
def delete_service(id, srvs_id):

    service=Service.query.filter_by(id=srvs_id).first_or_404()
    service_area=ServiceAreaAssociation.query.filter_by(service_id=srvs_id).all()

    review=Review.query.filter_by(service_id=srvs_id).all()

    service_request=ServiceRequest.query.filter_by(service_id=srvs_id).all()

    for req in service_request:
        reject=RejectedService.query.filter_by(service_request_id=req.id).all()
        for obj in reject:
            db.session.delete(obj)

    for obj in service_area:
        db.session.delete(obj)

    for obj in review:
        db.session.delete(obj)

    for obj in service_request:
        db.session.delete(obj)

    db.session.delete(service)
    db.session.commit()

    flash('Service had been deleted!','warning')

    return redirect(url_for('services',id=id))
#==================End Of Admin Control===========================#


#==================Professionals Control===========================#
def get_professional(id):
    user_prof = User.query.filter_by(id=id).first_or_404()
    professional = Professional.query.filter_by(user_id=id).first_or_404()
    adrs = Address.query.filter_by(user_id=id).first_or_404()

     # Convert binary image data to Base64
    picture_base64=''
    if professional.picture:
        picture_base64 = base64.b64encode(professional.picture).decode('utf-8')

    return {
        "id":user_prof.id, 'prof_id':professional.id, 'type':professional.service_type,
        "fname":professional.fname, "lname":professional.lname, "email":user_prof.email,
        "phone":professional.phone_no, "state":adrs.state, "city":adrs.city,"experience":professional.experience,
        "street":adrs.street, "zipcode":adrs.zipcode, "is_verified":professional.is_verified,
        "picture":picture_base64, "mimetype":'image/png',"created_at":user_prof.created_at
    }

@HomeEase.route('/HomeEase/professioinal/<int:id>/home')
@login_required
def professional_home(id):
    professional=get_professional(id)
    services = Service.query.filter_by(category=professional['type']).all()
    rejected = RejectedService.query.filter_by(professional_id=professional['prof_id']).all()
    
    rejected_req = [rej.service_request_id for rej in rejected]
    
    req_detail = []
    active = []
    closed = []

    for service in services:
        requests = service.service_requests
        for req in requests:
            if req.id not in rejected_req:
                cust = Customer.query.filter_by(id = req.customer_id).first_or_404()
                cust_addr = Address.query.filter_by(user_id=cust.user_id).first_or_404()
                srvs = Service.query.filter_by(id=req.service_id).first_or_404()

                if req.service_status=='requested':
                    req_detail.append((cust, cust_addr, srvs, req))

                elif req.service_status=='accepted':
                    active.append((cust, cust_addr, srvs, req))

                elif req.service_status=='closed':
                    reviewed = Review.query.filter_by(request_id=req.id).first()
                    closed.append((cust, cust_addr, srvs, req, reviewed))
                   
                    

    
    return render_template('/Professional/home.html', professional=professional, 
    req_detail=req_detail, active=active, closed=closed)

@HomeEase.route('/HomeEase/professioinal/<int:id>/home/accept_service/<int:request_id>')
@login_required
def accept_request(id, request_id):

    professional = Professional.query.filter_by(user_id=id).first_or_404()
    service_req = ServiceRequest.query.filter_by(id=request_id).first_or_404()

    if service_req.service_status=='accepted':
        return "<h3>Already Accepted by another professional, please refresh your page.</h3>"
    else:
        service_req.professional_id=professional.id
        service_req.service_status='accepted'

        db.session.add(service_req)
        db.session.commit()

    return redirect(url_for('professional_home', id=id))

@HomeEase.route('/HomeEase/professioinal/<int:id>/home/reject_service/<int:request_id>')
@login_required
def reject_request(id, request_id):

    professional = Professional.query.filter_by(user_id=id).first_or_404()

    reject = RejectedService(professional_id=professional.id, service_request_id=request_id)

    db.session.add(reject)
    db.session.commit()

    return redirect(url_for('professional_home', id=id))

@HomeEase.route('/HomeEase/professioinal/<int:id>/home/close_service/<int:request_id>')
@login_required
def close_request(id, request_id):
    service_req = ServiceRequest.query.filter_by(id=request_id).first_or_404()
    service_req.service_status = 'closed'
    service_req.date_of_completion = datetime.datetime.now()

    db.session.add(service_req)
    db.session.commit()
    return redirect(url_for('professional_home',id=id))

@HomeEase.route('/HomeEase/professioinal/<int:id>/search', methods=['GET', 'POST'])
@login_required
def professional_search(id):
    
    professional = get_professional(id)

    if not professional['is_verified']:
        return abort(403)

    if request.method=='POST':
        results=[]
        search_by=request.form.get('search_by')
        search_name=request.form.get('search_name').strip().lower()

        if search_by=='date':
            query_date = datetime.strptime(search_name, '%d/%m/%y').date()
            s_req=ServiceRequest.query.filter(func.date(ServiceRequest.date_of_request) == query_date,
                                                            ServiceRequest.service_status == 'requested').all()
            for req in s_req:
                srvs=Service.query.filter_by(id=req.service_id).first_or_404()
                cust=Customer.query.filter_by(id=req.customer_id).first_or_404()
                addr=Address.query.filter_by(user_id=cust.user_id).first_or_404()

                if srvs.category.strip().lower()==professional['type'].strip().lower():
                    results.append((req,srvs,cust,addr))
            return render_template('/Professional/search.html', professional=professional, results=results)

        elif search_by=='state':
            addr=Address.query.filter_by(state=search_name).all()
            for adr in addr:
                user=adr.user
                cust=Customer.query.filter_by(user_id=user.id).first()
                if cust:
                    req_all=ServiceRequest.query.filter_by(customer_id=cust.id, service_status = 'requested').all()
                    for req in req_all:
                        srvs=Service.query.filter_by(id=req.service_id).first_or_404()
                        if srvs.category.strip().lower()==professional['type'].strip().lower():
                            results.append((req,srvs,cust,adr))
            print(results)
            return render_template('/Professional/search.html', professional=professional, results=results)

        elif search_by=='city':
            addr=Address.query.filter_by(city=search_name).all()
            for adr in addr:
                user=adr.user
                cust=Customer.query.filter_by(user_id=user.id).first()
                if cust:
                    req_all=ServiceRequest.query.filter_by(customer_id=cust.id, service_status = 'requested').all()
                    for req in req_all:
                        srvs=Service.query.filter_by(id=req.service_id).first_or_404()
                        if srvs.category.strip().lower()==professional['type'].strip().lower():
                            results.append((req,srvs,cust,adr))
            return render_template('/Professional/search.html', professional=professional, results=results)

        elif search_by=='zipcode':
            addr=Address.query.filter_by(zipcode=search_name).all()
            for adr in addr:
                user=adr.user
                cust=Customer.query.filter_by(user_id=user.id).first()
                if cust:
                    req_all=ServiceRequest.query.filter_by(customer_id=cust.id, service_status = 'requested').all()
                    for req in req_all:
                        srvs=Service.query.filter_by(id=req.service_id).first_or_404()
                        if srvs.category.strip().lower()==professional['type'].strip().lower():
                            results.append((req,srvs,cust,adr))
            return render_template('/Professional/search.html', professional=professional, results=results)
        else:
            return render_template('/Professional/search.html', professional=professional, results=results)

    return render_template('/Professional/search.html', professional=professional, results='')

@HomeEase.route('/HomeEase/professioinal/<int:id>/summary')
@login_required
def professional_summary(id):
    
    professional = get_professional(id)

    if not professional['is_verified']:
        return abort(403)
    
    

    all_req=ServiceRequest.query.filter_by(professional_id=professional['prof_id']).all()

    infor={
        "Requests":{
            "total":len(all_req),
            "closed":len([req for req in all_req if req.service_status=='closed']),
            "accepted":len([req for req in all_req if req.service_status=='accepted']),
            "rejected":len(RejectedService.query.filter_by(professional_id=professional["prof_id"]).all())
        }
    }

    print(infor)

    return render_template('/Professional/summary.html', professional=professional, infor=infor)

@HomeEase.route('/HomeEase/professioinal/<int:id>/profile')
@login_required
def professional_profile(id):
    
    professional = get_professional(id)

    if not professional['is_verified']:
        return abort(403)

    return render_template('/Professional/profile.html', data=professional)

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
@login_required
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

@HomeEase.route('/HomeEase/professional/<int:id>/update_information', methods=['GET', 'POST'])
@login_required
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

def get_customer(id):
    user_cust = User.query.filter_by(id=id).first_or_404()
    customer = Customer.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if customer.picture:
        picture_base64 = base64.b64encode(customer.picture).decode('utf-8')

    cust_data = {
        "id":user_cust.id,
        "fname":customer.fname, "lname":customer.lname, "email":user_cust.email,
        "picture":picture_base64, "mimetype":'image/png'
    }
    return cust_data

def get_request(id):
    request_data = []
    cust = Customer.query.filter_by(user_id=id).first_or_404()
    requests = ServiceRequest.query.filter_by(customer_id=cust.id).all()
    
    if requests != []:
        for request in requests:
            is_reviewd=False
            service = Service.query.filter_by(id = request.service_id).first_or_404()
            reviewed = Review.query.filter_by(request_id=request.id).first()
            if reviewed:
                is_reviewd=True
            if request.professional_id:
                prof = Professional.query.filter_by(id = request.professional_id).first_or_404()
                request_data.append((request,service,prof,cust,is_reviewd))
            else:
                request_data.append((request,service,'',cust,is_reviewd))
        
        return request_data
    else:
        return []

@HomeEase.route('/HomeEase/customer/<int:id>/home')
@login_required
def customer_home(id):
    requests=get_request(id)
    return render_template('/Customer/home.html', customer=get_customer(id), requests=requests)

@HomeEase.route('/HomeEase/customer/<int:id>/<string:name>')
@login_required
def customer_viewService(id, name):
    services = Service.query.filter_by(category=name.lower()).all()
    
    return render_template('/Customer/viewService.html', customer=get_customer(id), services = services, name = name, requests=get_request(id))

@HomeEase.route('/HomeEase/customer/<int:id>/<string:name>/<int:srvs_id>/request')
@login_required
def customer_serviceRequest(id, name, srvs_id):
    cust=Customer.query.filter_by(user_id=id).first_or_404()
    request = ServiceRequest(service_id=srvs_id, customer_id=cust.id)
    
    db.session.add(request)
    db.session.commit()
    return redirect(url_for('customer_viewService', id=id, name=name))

@HomeEase.route('/HomeEase/customer/<int:id>/review/<int:req_id>')
@login_required
def customer_review(id, req_id):
    service_req = ServiceRequest.query.filter_by(id=req_id).first_or_404()
    prof = Professional.query.filter_by(id=service_req.professional_id).first_or_404()
    service = Service.query.filter_by(id=service_req.service_id).first_or_404()
    reviewed = Review.query.filter_by(request_id=req_id).first()

    if reviewed:
        return "<h3>Review Already Submitted, please go back and refresh the page.</h3>"
    
    return render_template('/Customer/review.html', customer=get_customer(id), 
                    req=service_req,prof=prof, service=service)

@HomeEase.route('/HomeEase/customer/<int:id>/review/<int:req_id>/submit', methods=['GET', 'POST'])
@login_required
def submit_review(id, req_id):
    cust = Customer.query.filter_by(user_id=id).first_or_404()
    service_req = ServiceRequest.query.filter_by(id=req_id).first_or_404()
    service = Service.query.filter_by(id=service_req.service_id).first_or_404()
    if request.method=='POST':
        star = int(request.form.get('rating'))
        remark = request.form.get('remark')
        
        if remark == "":
            review = Review(request_id=req_id, service_id=service.id, customer_id=cust.id, stars=star)
        else:
            review = Review(request_id=req_id, service_id=service.id, customer_id=cust.id, stars=star, remark=remark.strip())

        db.session.add(review)

        service_req.service_status = 'closed'
        service_req.date_of_completion = datetime.now()

        # Calculating Review Rating Star.
        review_count = int(service.review_count) + 1
        rating = int(service.rating)+star
        new_rating = rating/review_count

        service.rating = round(new_rating,1)
        service.review_count = review_count
        
        db.session.add(service)
        db.session.add(service_req)

        db.session.commit()

    return redirect(url_for('customer_home', id=id))

@HomeEase.route('/HomeEase/customer/<int:id>/search', methods=['GET', 'POST'])
@login_required
def customer_search(id):
    if request.method=='POST':
        results=[]
        search_by=request.form.get('search_by')
        search_name=request.form.get('search_name').strip().lower()

        if search_by=='service name':
            all_service=Service.query.all()
            for service in all_service:
                name=service.name.lower()
                if search_name in name or name in search_name or name==search_name:
                    results.append(service)
            return render_template('/Customer/search.html', customer=get_customer(id), results=results)

        elif search_by=='state':
            areas=ServiceArea.query.filter_by(state=search_name).all()
            for area in areas:
                service=area.services
                results.extend(service)
            return render_template('/Customer/search.html', customer=get_customer(id), results=results)

        elif search_by=='city':
            areas=ServiceArea.query.filter_by(city=search_name).all()
            for area in areas:
                service=area.services
                results.extend(service)
            return render_template('/Customer/search.html', customer=get_customer(id), results=results)  

        elif search_by=='zipcode':
            areas=ServiceArea.query.filter_by(zipcode=search_name).all()
            for area in areas:
                service=area.services
                results.extend(service)
            return render_template('/Customer/search.html', customer=get_customer(id), results=results)

        else:
            return render_template('/Customer/search.html', customer=get_customer(id), results=results)

    return render_template('/Customer/search.html', customer=get_customer(id), results='')

@HomeEase.route('/HomeEase/customer/<int:id>/summary')
@login_required
def customer_summary(id):
    cust=Customer.query.filter_by(user_id=id).first_or_404()
    requests=ServiceRequest.query.filter_by(customer_id=cust.id).all()
    services=Service.query.all()
    reviews=Review.query.filter_by(customer_id=cust.id).all()

    infor={
        "Requests":{
            "total":len(requests),
            "requested":len([req for req in requests if req.service_status=='requested']),
            "closed":len([req for req in requests if req.service_status=='closed']),
            "accepted":len([req for req in requests if req.service_status=='accepted']),
        },
        "Reviews":{
            "total":len(reviews),
        },
        "Service":{
            "available":len(services)
        }
    }

    print(infor)

    return render_template('/Customer/summary.html', customer=get_customer(id), infor=infor)

@HomeEase.route('/HomeEase/customer/<int:id>/profile')
@login_required
def customer(id):

    user_cust = User.query.filter_by(id=id).first_or_404()
    customer = Customer.query.filter_by(user_id=id).first_or_404()
    adrs = Address.query.filter_by(user_id=id).first_or_404()

    picture_base64=''
    if customer.picture:
        picture_base64 = base64.b64encode(customer.picture).decode('utf-8')

    cust_data = {
        "id":user_cust.id,
        "fname":customer.fname, "lname":customer.lname, "email":user_cust.email,
        "created_at":user_cust.created_at,
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
@login_required
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
@login_required
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
    return abort(405)

#==================Customers Control End===========================#

if __name__ == "__main__":
    HomeEase.run(debug=True)