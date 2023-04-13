from flask import Flask, render_template, flash, redirect, url_for, request, session, logging
#from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, RadioField, SelectField, IntegerField
from wtforms.fields import DateField, EmailField, TelField
from passlib.hash import sha256_crypt
#from flask_script import Manager
from functools import wraps
from datetime import datetime
from sqlalchemy import create_engine, text
import os

app = Flask(__name__)

db_connection_string = os.environ['DB_CONNECTION_STRING']
#print(db_connection_string)
engine = create_engine(db_connection_string,
                       connect_args={"ssl": {
                         "ssl_ca": "/etc/ssl/cert.pem"
                       }})

mysql = engine.connect()


def is_logged_in(f):

  @wraps(f)
  def wrap(*args, **kwargs):
    if 'logged_in' in session:
      return f(*args, **kwargs)
    else:
      flash('Nice try, Tricks don\'t work, bud!! Please Login :)', 'danger')
      return redirect(url_for('login'))

  return wrap


def is_trainor(f):

  @wraps(f)
  def wrap(*args, **kwargs):
    if session['prof'] == 3:
      return f(*args, **kwargs)
    else:
      flash('You are probably not a trainor!!, Are you?', 'danger')
      return redirect(url_for('login'))

  return wrap


def is_admin(f):

  @wraps(f)
  def wrap(*args, **kwargs):
    if session['prof'] == 1:
      return f(*args, **kwargs)
    else:
      flash('You are probably not an admin!!, Are you?', 'danger')
      return redirect(url_for('login'))

  return wrap


def is_recep_level(f):

  @wraps(f)
  def wrap(*args, **kwargs):
    if session['prof'] <= 2:
      return f(*args, **kwargs)
    else:
      flash('You are probably not an authorised to view that page!!', 'danger')
      return redirect(url_for('login'))

  return wrap


@app.route('/')
def index():
  return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    username = request.form['username']
    password_candidate = request.form['password']
    cur = mysql
    query = "select * from info where username = '" + username + "'"
    result = cur.execute(text(query))
    rows = result.all()
    data = {}
    #print(result)
    if len(rows) > 0:
      for row in rows:
        data = row._mapping
        password = data['password']

      if sha256_crypt.verify(password_candidate, password):
        session['logged_in'] = True
        session['username'] = username
        session['prof'] = data['prof']
        #session['hash'] = sha256_crypt.encrypt(username)
        flash('You are logged in', 'success')
        if session['prof'] == 1:
          #print("test2", url_for('adminDash'))
          return redirect(url_for('adminDash'))
        if session['prof'] == 3:
          return redirect(url_for('trainorDash'))
        if session['prof'] == 2:
          return redirect(url_for('recepDash'))
        #s = 'memberDash/%s', (username)
        return redirect(url_for('memberDash', username=username))
      else:
        error = 'Invalid login'
        return render_template('login.html', error=error)
    else:
      error = 'Username NOT FOUND'
      return render_template('login.html', error=error)

  return render_template('login.html')


class ChangePasswordForm(Form):
  old_password = PasswordField('Existing Password')
  new_password = PasswordField('Password', [
    validators.DataRequired(),
    validators.EqualTo('confirm',
                       message='Passwords aren\'t matching pal!, check \'em')
  ])
  confirm = PasswordField('Confirm Password')


@app.route('/update_password/<string:username>', methods=['GET', 'POST'])
def update_password(username):
  form = ChangePasswordForm(request.form)
  if request.method == 'POST' and form.validate():
    new = form.new_password.data
    entered = form.old_password.data
    cur = mysql
    ds = cur.execute(text("SELECT * FROM info WHERE username = :val"),
                     {"val": username})
    rows = ds.mappings().all()
    data = dict(rows[0])
    old = data['password']
    #cur.execute(text("SELECT password FROM info WHERE username = %s", [username]))
    #old = (cur.fetchone())['password']
    if sha256_crypt.verify(entered, old):
      query = "update info set password = '" + sha256_crypt.encrypt(
        new) + "' where username = '" + username + "'"
      cur.execute(text(query))
      flash('New password will be in effect from next login!!', 'info')
      if session['prof'] == 1:
        return redirect(url_for('adminDash'))
      if session['prof'] == 3:
        return redirect(url_for('trainorDash'))
      if session['prof'] == 2:
        return redirect(url_for('recepDash'))
      return redirect(url_for('memberDash', username=session['username']))
    #cur.close()
    flash('Old password you entered is wrong!!, try again', 'warning')
  return render_template('updatePassword.html', form=form)


@app.route('/adminDash')
@is_logged_in
#@is_admin
def adminDash():
  return render_template('adminDash.html')


values = []
choices = []


class AddTrainorForm(Form):
  name = StringField('Name', [validators.Length(min=1, max=100)])
  username = StringField('Username', [
    validators.InputRequired(),
    validators.NoneOf(values=values,
                      message="Username already taken, Please try another")
  ])
  password = PasswordField('Password', [
    validators.DataRequired(),
    validators.EqualTo('confirm',
                       message='Passwords aren\'t matching pal!, check \'em')
  ])
  confirm = PasswordField('Confirm Password')
  street = StringField('Street', [validators.Length(min=1, max=100)])
  city = StringField('City', [validators.Length(min=1, max=100)])
  prof = 3
  phone = StringField('Phone', [validators.Length(min=1, max=100)])


@app.route('/addTrainor', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def addTrainor():
  values.clear()
  cur = mysql
  ds = cur.execute(text("SELECT username FROM info"))
  data = ds.all()
  for row in data:
    values.append(row._mapping)
  #app.logger.info(b[0]['username'])
  #res = values.fetchall()
  #app.logger.info(res)
  #cur.close()
  form = AddTrainorForm(request.form)
  if request.method == 'POST' and form.validate():
    #app.logger.info("setzdgxfhcgjvkhbjlkn")
    name = form.name.data
    username = form.username.data
    password = sha256_crypt.encrypt(str(form.password.data))
    street = form.street.data
    city = form.city.data
    prof = 3
    phone = form.phone.data

    cur = mysql
    query = text(
      "INSERT INTO info(name, username, password, street, city, prof, phone) VALUES (:name, :username, :email, :street, :city, :prof, :phone)"
    )

    cur.execute(
      query, {
        'name': name,
        'username': username,
        'email': password,
        'street': street,
        'city': city,
        'prof': prof,
        'phone': phone
      })

    query = text("INSERT INTO trainors(username) VALUES(:username)")
    cur.execute(query, {'username': username})

    flash('You recruited a new Trainor!!', 'success')
    return redirect(url_for('adminDash'))
  return render_template('addTrainor.html', form=form)


class DeleteRecepForm(Form):
  username = SelectField(u'Choose which one you wanted to delete',
                         choices=choices)


@app.route('/deleteTrainor', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def deleteTrainor():
  choices.clear()
  cur = mysql
  ds = cur.execute(text("SELECT username FROM trainors"))
  data = ds.all()
  for row in data:
    value = row._mapping
    tup = (value['username'], value['username'])
    choices.append(tup)

  form = DeleteRecepForm(request.form)
  if len(choices) == 1:
    flash('You cannot remove your only Trainor!!', 'danger')
    return redirect(url_for('adminDash'))
  if request.method == 'POST':
    #app.logger.info(form.username.data)
    username = form.username.data
    ds = cur.execute(text("SELECT * FROM trainors WHERE username != :val"),
                     {"val": username})
    rows = ds.mappings().all()
    result = dict(rows[0])
    new = result['username']

    query = text("UPDATE members set trainor=:new where trainor=:username")
    cur.execute(query, {'new': new, 'username': username})
    cur.execute(text("DELETE FROM trainors WHERE username =: username"),
                {'username': username})
    cur.execute(text("DELETE FROM info WHERE username =: username"),
                {'username': username})
    #mysql.connection.commit()
    #cur.close()
    choices.clear()
    flash('You removed your Trainor!!', 'success')
    return redirect(url_for('adminDash'))
  return render_template('deleteRecep.html', form=form)


@app.route('/addRecep', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def addRecep():
  values.clear()
  cur = mysql
  ds = cur.execute(text("SELECT username FROM info"))
  data = ds.all()
  for row in data:
    value = row._mapping
    values.append(value['username'])

  #app.logger.info(b[0]['username'])
  #res = values.fetchall()
  #app.logger.info(res)
  #cur.close()
  form = AddTrainorForm(request.form)
  if request.method == 'POST' and form.validate():
    #app.logger.info("setzdgxfhcgjvkhbjlkn")
    name = form.name.data
    username = form.username.data
    password = sha256_crypt.encrypt(str(form.password.data))
    street = form.street.data
    city = form.city.data
    phone = form.phone.data

    cur = mysql
    cur.execute(
      text(
        "INSERT INTO info(name, username, password, street, city, prof, phone) VALUES(:name, :username, :password, :street, :city, :prof, :phone)"
      ), {
        'name': name,
        'username': username,
        'password': password,
        'street': street,
        'city': city,
        'prof': 3,
        'phone': phone
      })

    cur.execute(text("INSERT INTO receps(username) VALUES(:username)"),
                {'username': username})
    #mysql.connection.commit()
    #cur.close()
    flash('You recruited a new Receptionist!!', 'success')
    return redirect(url_for('adminDash'))
  return render_template('addRecep.html', form=form)


class DeleteRecepForm(Form):
  username = SelectField(u'Choose which one you wanted to delete',
                         choices=choices)


@app.route('/deleteRecep', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def deleteRecep():
  choices.clear()
  cur = mysql
  ds = cur.execute(text("SELECT username FROM receps"))
  data = ds.all()
  for row in data:
    value = row._mapping
    tup = (value['username'], value['username'])
    choices.append(tup)

  if len(choices) == 1:
    flash('You cannot remove your only receptionist!!', 'danger')
    return redirect(url_for('adminDash'))
  form = DeleteRecepForm(request.form)
  if request.method == 'POST':
    #app.logger.info(form.username.data)
    username = form.username.data
    cur.execute(text("DELETE FROM receps WHERE username = :username"),
                {'username': username})
    cur.execute(text("DELETE FROM info WHERE username = :username"),
                {'username': username})
    #mysql.connection.commit()
    #cur.close()
    choices.clear()
    flash('You removed your receptionist!!', 'success')
    return redirect(url_for('adminDash'))
  return render_template('deleteRecep.html', form=form)


class AddEquipForm(Form):
  name = StringField('Name', [validators.Length(min=1, max=100)])
  count = IntegerField('Count', [validators.NumberRange(min=1, max=25)])


@app.route('/addEquip', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def addEquip():
  form = AddEquipForm(request.form)
  if request.method == 'POST' and form.validate():
    name = form.name.data
    count = form.count.data
    cur = mysql
    equips = []
    ds = cur.execute(text("SELECT name FROM equip"))
    data = ds.all()
    for row in data:
      value = row._mapping
      equips.append(value['name'])

    if name in equips:
      cur.execute(text("UPDATE equip SET count = :count WHERE name = :name"), {
        'count': count,
        'name': name
      })
    else:
      cur.execute(text("INSERT INTO equip(name, count) VALUES(:name, :count)"),
                  {
                    'name': name,
                    'count': count
                  })
    #mysql.connection.commit()
    #cur.close()
    flash('You added a new Equipment!!', 'success')
    return redirect(url_for('adminDash'))
  return render_template('addEquip.html', form=form)


class RemoveEquipForm(Form):
  name = RadioField('Name', choices=choices)
  count = IntegerField('Count', [validators.InputRequired()])


@app.route('/removeEquip', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def removeEquip():
  choices.clear()
  cur = mysql
  ds = cur.execute(text("SELECT name FROM equip"))
  dt = ds.all()
  for row in dt:
    value = row._mapping
    tup = (value['name'], value['name'])
    choices.append(tup)
  form = RemoveEquipForm(request.form)
  #num = data['count']
  if request.method == 'POST' and form.validate():
    ds = cur.execute(text("SELECT * FROM equip WHERE name = :name"),
                     {'name': [form.name.data]})
    data = ds.all()
    app.logger.info(data['count'])
    num = data['count']
    if num >= form.count.data and form.count.data > 0:
      name = form.name.data
      count = form.count.data
      cur = mysql
      cur.execute(
        text("UPDATE equip SET count = count-:count WHERE name =:name"), {
          'count': count,
          'name': name
        })
      #mysql.connection.commit()
      #cur.close()
      choices.clear()
      flash('You successfully removed some of your equipment!!', 'success')
      return redirect(url_for('adminDash'))
    else:
      flash('you must enter valid number', 'danger')
  return render_template('removeEquip.html', form=form)


choices2 = []


class AddMemberForm(Form):
  name = StringField('Name', [validators.Length(min=1, max=50)])
  username = StringField('Username', [
    validators.InputRequired(),
    validators.NoneOf(values=values,
                      message="Username already taken, Please try another")
  ])
  password = PasswordField('Password', [
    validators.DataRequired(),
    validators.EqualTo('confirm', message='Passwords do not match')
  ])
  confirm = PasswordField('Confirm Password')
  plan = RadioField('Select Plan', choices=choices)
  trainor = SelectField('Select Trainor', choices=choices2)
  street = StringField('Street', [validators.Length(min=1, max=100)])
  city = StringField('City', [validators.Length(min=1, max=100)])
  phone = StringField('Phone', [validators.Length(min=1, max=100)])


@app.route('/addMember', methods=['GET', 'POST'])
@is_logged_in
@is_recep_level
def addMember():
  choices.clear()
  choices2.clear()
  cur = mysql

  ds = cur.execute(text("SELECT username FROM info"))
  dt = ds.all()
  for row in dt:
    value = row._mapping
    values.append(value['username'])

  ds = cur.execute(text("SELECT DISTINCT name FROM plans"))
  dt = ds.all()
  for row in dt:
    value = row._mapping
    tup = (value['name'], value['name'])
    choices.append(tup)

  ds = cur.execute(text("SELECT username FROM trainors"))
  dt = ds.all()
  for row in dt:
    value = row._mapping
    tup = (value['username'], value['username'])
    choices2.append(tup)

  #cur.close()

  form = AddMemberForm(request.form)
  if request.method == 'POST' and form.validate():
    #app.logger.info("setzdgxfhcgjvkhbjlkn")
    name = form.name.data
    username = form.username.data
    password = sha256_crypt.encrypt(str(form.password.data))
    street = form.street.data
    city = form.city.data
    phone = form.phone.data
    plan = form.plan.data
    trainor = form.trainor.data
    cur = mysql
    cur.execute(
      text(
        "INSERT INTO info(name, username, password, street, city, prof, phone) VALUES(:name, :username, :password, :street, :city, :prof, :phone)"
      ), {
        'name': name,
        'username': username,
        'password': password,
        'street': street,
        'city': city,
        'prof': 4,
        'phone': phone
      })
    cur.execute(
      text(
        "INSERT INTO members(username, plan, trainor) VALUES(:username, :plan, :trainor)"
      ), {
        'username': username,
        'plan': plan,
        'trainor': trainor
      })
    #mysql.connection.commit()
    #cur.close()
    choices2.clear()
    choices.clear()
    flash('You added a new member!!', 'success')
    if (session['prof'] == 1):
      return redirect(url_for('adminDash'))
    return redirect(url_for('recepDash'))
  return render_template('addMember.html', form=form)


@app.route('/deleteMember', methods=['GET', 'POST'])
@is_logged_in
@is_recep_level
def deleteMember():
  choices.clear()
  cur = mysql
  ds = cur.execute(text("SELECT username FROM members"))
  dt = ds.all()
  for row in dt:
    value = row._mapping
    tup = (value['username'], value['username'])
    choices.append(tup)
  form = DeleteRecepForm(request.form)
  if request.method == 'POST':
    username = form.username.data
    cur = mysql
    cur.execute(text("DELETE FROM members WHERE username = :username"),
                {'username': username})
    cur.execute(text("DELETE FROM info WHERE username = :username"),
                {'username': username})
    #mysql.connection.commit()
    #cur.close()
    choices.clear()
    flash('You deleted a member from the GYM!!', 'success')
    if (session['prof'] == 1):
      return redirect(url_for('adminDash'))
    return redirect(url_for('recepDash'))
  return render_template('deleteRecep.html', form=form)


@app.route('/viewDetails')
def viewDetails():
  cur = mysql
  ds = cur.execute(
    text("SELECT username FROM info WHERE username != :username"),
    {'username': session['username']})
  dt = ds.all()
  result = []
  for row in dt:
    value = row._mapping
    result.append(value)

  return render_template('viewDetails.html', result=result)


@app.route('/recepDash')
@is_recep_level
def recepDash():
  return render_template('recepDash.html')


class trainorForm(Form):
  name = RadioField('Select Username', choices=choices)
  date = DateField('Date', format='%Y-%m-%d')
  report = StringField('Report', [validators.InputRequired()])
  rate = RadioField('Result',
                    choices=[('good', 'good'), ('average', 'average'),
                             ('poor', 'poor')])


@app.route('/trainorDash', methods=['GET', 'POST'])
@is_logged_in
@is_trainor
def trainorDash():
  choices.clear()
  cur = mysql
  ds = cur.execute(text("SELECT name, count FROM equip"))
  dt = ds.all()
  equips = []
  for row in dt:
    value = row._mapping
    equips.append(value)
  #app.logger.info(equips)
  ds = cur.execute(
    text("SELECT username FROM members WHERE trainor = :trainor"),
    {'trainor': session['username']})
  dt = ds.all()
  members_under = []
  for row in dt:
    value = row._mapping
    members_under.append(value)
  #cur.close()
  #cur = mysql

  ds = cur.execute(
    text("SELECT username FROM members WHERE trainor = :trainer"),
    {'trainer': session['username']})
  dt = ds.all()
  for row in dt:
    value = row._mapping
    tup = (value['username'], value['username'])
    choices.append(tup)
  #cur.close()

  form = trainorForm(request.form)

  if request.method == 'POST':
    date = form.date.data
    username = form.name.data
    report = form.report.data
    rate = form.rate.data
    if rate == 'good':
      rate = 1
    elif rate == 'average':
      rate = 2
    else:
      rate = 3
    #app.logger.info(request.form.input_date)
    #app.logger.info(date)
    if datetime.now().date() < date:
      flash('You cannot predict furture, buoy!!', 'warning')
      choices.clear()
      return redirect(url_for('trainorDash'))

    cur = mysql
    ds = cur.execute(
      text("SELECT date FROM progress WHERE username = :username"),
      {'username': username})
    entered = []
    dt = ds.all()
    for row in dt:
      value = row._mapping
      entered.append(value['date'])

    if date in entered:
      ds = cur.execute(
        text(
          "UPDATE progress SET daily_result = :report, rate = :rate WHERE username = :username and date = :date"
        ), {
          'report': report,
          'rate': rate,
          'username': username,
          'date': date
        })
      #mysql.connection.commit()
      #cur.close()
      choices.clear()
      flash('Succesfully updated!', 'success')
      return redirect(url_for('trainorDash'))

    cur.execute(
      text(
        "INSERT INTO progress(username, date, daily_result, rate) VALUES(:username, :date, :report, :rate)"
      ), {
        'username': username,
        'date': date,
        'report': report,
        'rate': rate
      })
    #mysql.connection.commit()
    #cur.close()
    choices.clear()
    flash('Progress updated and Reported', 'info')
    return redirect(url_for('trainorDash'))

  return render_template('trainorDash.html',
                         equips=equips,
                         form=form,
                         members=members_under)


class UpdatePlanForm(Form):
  name = StringField('Plan Name', [validators.Length(min=1, max=50)])
  exercise = StringField('Exercise', [validators.Length(min=1, max=100)])
  reps = IntegerField('Reps', [validators.NumberRange(min=1, max=20)])
  sets = IntegerField('Sets', [validators.NumberRange(min=1, max=20)])


@app.route('/updatePlans', methods=['GET', 'POST'])
@is_trainor
def updatePlans():
  form = UpdatePlanForm(request.form)
  if request.method == 'POST' and form.validate():
    name = form.name.data
    exercise = form.exercise.data
    reps = form.reps.data
    sets = form.sets.data
    cur = mysql
    ds = cur.execute(
      text(
        "SELECT name, exercise FROM plans WHERE name = :name and exercise = :exercise"
      ), {
        'name': name,
        'exercise': exercise
      })
    result = ds.mappings().all()
    if len(result) > 0:
      ds = cur.execute(
        text(
          "UPDATE plans SET sets=:sets, reps= :reps WHERE name = :name and exercise = :exercise"
        ), {
          'sets': sets,
          'reps': reps,
          'name': name,
          'exercise': exercise
        })
    else:
      ds = cur.execute(
        text(
          "INSERT INTO plans(name, exercise, sets, reps) VALUES(:name, :exercise, :sets, :reps)"
        ), {
          'name': name,
          'exercise': exercise,
          'sets': sets,
          'reps': reps
        })
    #mysql.connection.commit()
    #cur.close()
    flash('You have updated the plan schemes', 'success')
    return redirect(url_for('trainorDash'))
  return render_template('addPlan.html', form=form)


@app.route('/memberDash/<string:username>')
@is_logged_in
def memberDash(username):
  if session['prof'] == 4 and username != session['username']:
    flash('You aren\'t authorised to view other\'s Dashboards', 'danger')
    return redirect(url_for('memberDash', username=session['username']))
  cur = mysql
  ds = cur.execute(text("SELECT plan FROM members WHERE username = :username"),
                   {'username': username})
  #dt = ds.mappings().all()['plan']
  rows = ds.mappings().all()
  plan = dict(rows[0])['plan']
  q = cur.execute(
    text("SELECT exercise, reps, sets FROM plans WHERE name = :name"),
    {'name': plan})
  scheme = q.mappings().all()
  n = cur.execute(
    text(
      "SELECT date, daily_result, rate FROM progress WHERE username = :username ORDER BY date DESC"
    ), {'username': username})
  progress = n.mappings().all()
  result = []
  for row in progress:
    result.append(int(row['rate']))
  good = result.count(1)
  poor = result.count(3)
  average = result.count(2)
  total = good + poor + average
  if total > 0:
    good = round((good / total) * 100, 2)
    average = round((average / total) * 100, 2)
    poor = round((poor / total) * 100, 2)
  #cur.close()
  return render_template('memberDash.html',
                         user=username,
                         plan=plan,
                         scheme=scheme,
                         progress=progress,
                         good=good,
                         poor=poor,
                         average=average)


@app.route('/profile/<string:username>')
@is_logged_in
def profile(username):
  if username == session['username'] or session['prof'] == 1 or session[
      'prof'] == 2:
    cur = mysql
    ds = cur.execute(text("SELECT * FROM info WHERE username = :val"),
                     {"val": username})
    rows = ds.mappings().all()
    result = dict(rows[0])
    return render_template('profile.html', result=result)
  flash('You cannot view other\'s profile', 'warning')
  if session['prof'] == 3:
    return redirect(url_for('trainorDash'))
  return redirect(url_for('memberDash', username=username))


class EditForm(Form):
  name = StringField('Name', [validators.Length(min=1, max=50)])
  street = StringField('Street', [validators.Length(min=1, max=100)])
  city = StringField('City', [validators.Length(min=1, max=100)])
  phone = StringField('Phone', [validators.Length(min=1, max=100)])


@app.route('/edit_profile/<string:username>', methods=['GET', 'POST'])
@is_logged_in
def edit_profile(username):

  if username != session['username']:
    flash('You aren\'t authorised to edit other\'s details', 'warning')
    if session['prof'] == 4:
      return redirect(url_for('memberDash', username=username))
    if session['prof'] == 1:
      return redirect(url_for('adminDash'))
    if session['prof'] == 2:
      return redirect(url_for('recepDash', username=username))
    if session['prof'] == 3:
      return redirect(url_for('trainorDash', username=username))

  cur = mysql
  ds = cur.execute(text("SELECT * FROM info WHERE username = :username"),
                   {'username': username})
  dt = ds.mappings().all()
  result = dict(dt[0])
  form = EditForm(request.form)

  form.name.data = result['name']
  form.street.data = result['street']
  form.city.data = result['city']
  form.phone.data = result['phone']

  #cur.close()

  if request.method == 'POST' and form.validate():
    #app.logger.info("setzdgxfhcgjvkhbjlkn")
    name = request.form['name']
    street = request.form['street']
    city = request.form['city']
    phone = request.form['phone']
    app.logger.info(name)
    app.logger.info(street)
    app.logger.info(city)
    ds = cur.execute(
      text(
        "UPDATE info SET name = :name, street = :street, city = :city, phone = :phone WHERE username = :username"
      ), {
        'name': name,
        'street': street,
        'city': city,
        'phone': phone,
        'username': username
      })
    app.logger.info(ds)
    #mysql.connection.commit()
    #cur.close()
    flash('You successfully updated your profile!!', 'success')
    if session['prof'] == 4:
      return redirect(url_for('memberDash', username=username))
    if session['prof'] == 1:
      return redirect(url_for('adminDash'))
    if session['prof'] == 2:
      return redirect(url_for('recepDash', username=username))
    if session['prof'] == 3:
      return redirect(url_for('trainorDash', username=username))
  return render_template('edit_profile.html', form=form)


@app.route('/logout')
@is_logged_in
def logout():
  session.clear()
  flash('You are now logged out', 'success')
  return redirect(url_for('login'))


if __name__ == "__main__":
  app.config['SESSION_TYPE'] = 'filesystem'
  app.secret_key = '120423@GMS'
  app.debug = True
  #manager = Manager(app)
  #manager.secret_key = '528491@siva'
  #manager.run()
  #app.run()
  app.run(host='0.0.0.0', debug=True)
