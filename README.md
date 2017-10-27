# Overview
Item Catalog is a Flask app that allows users to store, edit, and delete their items in categories that they create. The categories and items within are publicly visible, however users can only modify items and categories that they created.

# Installation
The Item Catalog program requires the following in the runtime environment:

- Python (Version 2.7.12)
- The sqlalchemy library (Version 1.1.14)

All of these are included in a Vagrant file, which can be downloaded [here](https://d17h27t6h515a5.cloudfront.net/topher/2017/August/59822701_fsnd-virtual-machine/fsnd-virtual-machine.zip)

Vagrant can be obtained [here](https://www.vagrantup.com/downloads.html)

To make use of Vagrant, you'll also need VirtualBox, which can be downloaded [here](https://www.virtualbox.org/wiki/Downloads)

# Requirements
This program has been tested using Python 2.7.12. It may not work using other versions of Python.

# App Usage
From a terminal, navigate to the directory containing `application.py` and run either `./application.py` or `python application.py`

You should get output similar to
     ```
     Running on http://0.0.0.0:8000/ (Press CTRL+C to quit)
     ```

Once this message displays, you can use the app by directing a browser to `http://localhost:8000` and get started!

# API Usage
The Item Catalog offers a couple public endpoints for querying data. These are read-only, and all use a base URL of `localhost:8000/`

### `catalog/JSON`
Return JSON of all categories and their respective items

### `category/JSON`
Return JSON of all categories

### `category/<category_id>/item/JSON`
Return JSON of all items for the specified category

### `category/<category_id>/item/<item_id>/JSON`
Return JSON for the item requested

