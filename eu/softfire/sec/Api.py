import bottle
# from cork import Cork
from beaker.middleware import SessionMiddleware
from bottle import request, get, static_file
from sdk.softfire.utils import get_config
import eu.softfire.sec.utils.utils as utils

from eu.softfire.sec.utils.utils import *


# aaa = Cork(get_config("api", "cork-files-path", config_file_path=config_path))
# authorize = aaa.make_auth_decorator(fail_redirect="/login")
# bottle.TEMPLATE_PATH = [get_config('api', 'view-path', config_path)]

logger = utils.get_logger(utils.config_path, __name__)
REST_HOST = "0.0.0.0"
PORT = 4096

@get('/<resource>/<id>')
# @authorize()
def download_scripts(id, resource):
    file_path = get_config(section="local-files", key="path", config_file_path=config_path)


    logger.info("incoming request")
    # username = aaa.current_user.username

    '''
    resources_db = '%s/security-manager.db' % local_files_path
    conn = sqlite3.connect(resources_db)
    cur = conn.cursor()
    res = cur.execute('SELECT * FROM resources WHERE  username = "%s" AND random_id = "%s"' % (username, id))

    if len(res.fetchall()) == 0 :
        conn.close()
        return bottle.HTTPResponse(status=403)
    conn.close()
    '''

    if resource == "dashboard":
        ext = ".html"
        download = False
    else:
        ext = ".tar"
        download = True

    tmp_file_path = "%s/tmp" % file_path
    if resource == "dashboard":
        filename = "%s/%s%s" % (id, resource, ext)
    else:
        filename = "%s/%s-%s%s" % (id, resource, id, ext)

    logger.debug("%s-%s" % (tmp_file_path, filename))

    try:
        f = static_file(filename, tmp_file_path, download=download)
    except Exception:
        f = "ERROR"
    return f


'''
@bottle.post('/register')
def register():
    """Send out registration email"""
    #logger.debug(("got body: %s" % request.body.read().decode("utf-8")))
    aaa.create_user(post_get('username'), 'user', post_get('password'))
    return 'User created'

@bottle.route('/login')
@bottle.view('login_form')
def login_form():
    """Serve login form"""
    return {}

@bottle.route('/list_resources')
@bottle.view('list_resources')
def list_resources():
    username = aaa.current_user.username
    """Serve login form"""
    return {"username" : username}

@bottle.post('/login')
def login(referrer=None):
    """Authenticate users"""
    print(bottle.request.remote_route)
    username = post_get('username')
    password = post_get('password')
    if not aaa.login(username, password):
        return dict(ok=False, msg="Username or password invalid")


@bottle.route('/logout')
def logout():
	aaa.logout(success_redirect='/login')
'''


class StartThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.stopped = False

    def run(self):
        start()


#########
# Utils #
#########
'''
def error_translation(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            traceback.print_exc()
            bottle.abort(400, e.args)
        except exceptions.ExperimentNotFound as e:
            traceback.print_exc()
            bottle.abort(404, e.message)
        except exceptions.ExperimentValidationError as e:
            traceback.print_exc()
            bottle.abort(400, e.message)
        except exceptions.ManagerNotFound as e:
            traceback.print_exc()
            bottle.abort(404, e.message)
        except exceptions.ResourceAlreadyBooked as e:
            traceback.print_exc()
            bottle.abort(400, e.message)
        except exceptions.ResourceNotFound as e:
            traceback.print_exc()
            bottle.abort(404, e.message)
        except exceptions.RpcFailedCall:
            traceback.print_exc()
            bottle.abort(500, "Ups, an internal error occurred, please report to us the procedure and we will fix it")
        except FileNotFoundError:
            traceback.print_exc()
            bottle.abort(404, "File not found in your request")
        # except:
        #     traceback.print_exc()
        #     bottle.abort(500, "Ups, an internal error occurred, please report to us the procedure and we will fix it")

    return wrapper

'''


def postd():
    return bottle.request.forms


def post_get(name, default=''):
    try:
        return json.loads(request.body.read().decode("utf-8")).get(name, default)
    except:
        return bottle.request.POST.get(name, default).strip()


def check_if_authorized(username):
    authorized_experimenter_file = get_config('api', 'authorized-experimenters',
                                              '/etc/softfire/authorized-experimenters.json')
    if os.path.exists(authorized_experimenter_file) and os.path.isfile(authorized_experimenter_file):
        with open(authorized_experimenter_file, "r") as f:
            authorized_exp = json.loads(f.read().encode("utf-8"))
            return authorized_exp.get(username) and bool(authorized_exp[username])
    else:
        return False


def start():
    bottle.debug(True)

    #TODO forward change to .ini file
    port = get_config(config_file_path=config_path, section='api', key='port', default=8080)
    app = bottle.app()
    # bottle.install(error_translation)

    session_opts = {
        'session.cookie_expires': True,
        # 'session.encrypt_key': get_config('api', 'encrypt_key', 'softfire'),
        'session.httponly': True,
        'session.timeout': 3600 * 24,  # 1 day
        'session.type': 'cookie',
        'session.validate_key': True,
    }
    app = SessionMiddleware(app, session_opts)
    # quiet_bottle = logger.getEffectiveLevel() < logging.DEBUG
    # logger.debug("Bootlepy quiet mode: %s" % quiet_bottle)
    
    logger.info("Starting want-agent REST server. listening on %s:%s" % (REST_HOST, PORT))
    bottle.run(app=app, port=PORT, host=REST_HOST)
