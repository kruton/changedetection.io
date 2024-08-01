
import quart_flask_patch

from quart import Blueprint, redirect, url_for
from flask_login import login_required
from changedetectionio.store import ChangeDetectionStore
from changedetectionio import queuedWatchMetaData
from asyncio import PriorityQueue

PRICE_DATA_TRACK_ACCEPT = 'accepted'
PRICE_DATA_TRACK_REJECT = 'rejected'

def construct_blueprint(datastore: ChangeDetectionStore, update_q: PriorityQueue[queuedWatchMetaData.PrioritizedItem]):

    price_data_follower_blueprint = Blueprint('price_data_follower', __name__)

    @login_required
    @price_data_follower_blueprint.route("/<string:uuid>/accept", methods=['GET'], endpoint='accept')
    async def accept(uuid):
        datastore.data['watching'][uuid]['track_ldjson_price_data'] = PRICE_DATA_TRACK_ACCEPT
        datastore.data['watching'][uuid]['processor'] = 'restock_diff'
        datastore.data['watching'][uuid].clear_watch()
        await update_q.put(queuedWatchMetaData.PrioritizedItem(priority=1, item={'uuid': uuid, 'skip_when_checksum_same': False}))
        return redirect(url_for("index"))

    @login_required
    @price_data_follower_blueprint.route("/<string:uuid>/reject", methods=['GET'], endpoint='reject')
    def reject(uuid):
        datastore.data['watching'][uuid]['track_ldjson_price_data'] = PRICE_DATA_TRACK_REJECT
        return redirect(url_for("index"))


    return price_data_follower_blueprint


