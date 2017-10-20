#!/usr/bin/env python
import json
import random
import string
import logging
import httplib2
import requests
from database_setup import Base, Category, Item, User
from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import make_response, flash
from flask import session as login_session
from functools import wraps
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Helper to check login status
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


# JSON APIs to view Item Catalog Information
@app.route('/catalog/JSON')
def catalog_json():
    """Return JSON of all categories and their respective items"""
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize_all for c in categories])


@app.route('/category/JSON')
def categories_json():
    """Return JSON of all categories"""
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/category/<int:category_id>/item/JSON')
def category_item_json(category_id):
    """Return JSON of all items for the specified category"""
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def item_json(category_id, item_id):
    """Return JSON for the item requested"""
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# User Helper Functions
def create_user(current_session):
    new_user = User(name=current_session['username'], email=current_session[
                   'email'], picture=current_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=current_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as e:
        logging.exception(e)
        return None


# Login page
@app.route('/login')
def show_login():
    # Create anti-forgery state token
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        flash("User already logged in!")
        return url_for('show_categories')

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # Set login session provider
    login_session['provider'] = 'google'

    # If user doesn't exist, create one
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    flash("Welcome, "+login_session['username']+"!")
    return url_for('show_categories')


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        del login_session['access_token']
        response = make_response(
            json.dumps('Failed to revoke token for given user. '
                       'Access token reset.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Show all categories
@app.route('/')
@app.route('/category/')
def show_categories():
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('public-categories.html',
                               categories=categories)
    else:
        return render_template('categories.html',
                               categories=categories)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def new_category():
    if request.method == 'POST':
        category = Category(
            name=request.form['name'],
            description=request.form['description'],
            user_id=login_session['user_id'])
        session.add(category)
        flash('New Category %s Successfully Created' % category.name)
        session.commit()
        return redirect(url_for('show_categories'))
    else:
        return render_template('new-category.html')


# Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    edited_category = session.query(
        Category).filter_by(id=category_id).one()
    if edited_category.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to edit this category. Please create your own category in " \
               "order to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            edited_category.name = request.form['name']
        if request.form['description']:
            edited_category.description = request.form['description']
        flash('Category Successfully Edited %s' % edited_category.name)
        return redirect(url_for('show_categories'))
    else:
        return render_template('edit-category.html',
                               category=edited_category)


# Delete a category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    category_to_delete = session.query(
        Category).filter_by(id=category_id).one()
    if category_to_delete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to delete this category. Please create your own category" \
               " in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(category_to_delete)
        flash('%s Successfully Deleted' % category_to_delete.name)
        session.commit()
        return redirect(url_for('show_categories',
                                category_id=category_id))
    else:
        return render_template('delete-category.html',
                               category=category_to_delete)


# Show a category's items
@app.route('/category/<category_id>/')
@app.route('/category/<category_id>/item/')
def show_category_items(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = get_user_info(category.user_id)
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    if 'username' not in login_session:
        return render_template('public-item.html',
                               items=items,
                               category=category,
                               creator=creator)
    elif creator.id != login_session['user_id']:
        return render_template('restricted-item.html',
                               items=items,
                               category=category,
                               creator=creator)
    else:
        return render_template('item.html',
                               items=items,
                               category=category,
                               creator=creator)


# Create a new item
@app.route('/category/<int:category_id>/item/new/', methods=['GET', 'POST'])
@login_required
def new_item(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to add items to this category. Please create your own " \
               "category in order to add items.');}</script><body" \
               " onload='myFunction()'>"
    if request.method == 'POST':
        item = Item(name=request.form['name'],
                    description=request.form['description'],
                    category_id=category_id,
                    user_id=category.user_id)
        session.add(item)
        session.commit()
        flash('New %s Item Successfully Created' % item.name)
        return redirect(url_for('show_category_items',
                                category_id=category_id))
    else:
        return render_template('new-item.html',
                               category_id=category_id)


# Edit an item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def edit_item(category_id, item_id):
    edited_item = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to edit items in this category. Please create your own" \
               " category in order to edit items.');}</script><body" \
               " onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            edited_item.name = request.form['name']
        if request.form['description']:
            edited_item.description = request.form['description']
        session.add(edited_item)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('show_category_items',
                                category_id=category_id))
    else:
        return render_template('edit-item.html',
                               category_id=category_id,
                               item_id=item_id,
                               item=edited_item)


# Delete an item
@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def delete_item(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item_to_delete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not " \
               "authorized to delete items from this category. Please create" \
               " your own category in order to delete items.');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('show_category_items',
                                category_id=category_id))
    else:
        return render_template('delete-item.html',
                               item=item_to_delete,
                               category_id=category_id)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        del login_session['provider']
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        flash("You have successfully been logged out.")
        return redirect(url_for('show_categories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_categories'))


if __name__ == '__main__':
    app.secret_key = 'my_secret_app_key'
    app.debug = False
    app.run(host='0.0.0.0', port=8000)
