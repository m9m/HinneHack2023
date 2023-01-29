from flask import Blueprint, render_template, abort

route = Blueprint('route', __name__,
                        template_folder='templates')