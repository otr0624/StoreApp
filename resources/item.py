from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from models.item import ItemModel

BLANK_ERROR = "{} cannot be left blank."
ITEM_NOT_FOUND = "Item not found."
NAME_ALREADY_EXISTS = "An item with name {} already exists."
ERROR_INSERTING = "An error occurred while inserting the item."
ITEM_DELETED = "Item deleted."


class Item(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument(
        "price", type=float, required=True, help=BLANK_ERROR.format("Price")
    )
    parser.add_argument(
        "store_id", type=int, required=True, help=BLANK_ERROR.format("Store ID")
    )

    @classmethod
    @jwt_required
    def get(cls, name: str):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {"message": ITEM_NOT_FOUND}, 404

    @classmethod
    @jwt_required
    def post(cls, name: str):
        if ItemModel.find_by_name(name):
            return (
                {"message": NAME_ALREADY_EXISTS.format(name)},
                400,
            )

        data = Item.parser.parse_args()

        item = ItemModel(name, **data)

        try:
            item.save_to_db()
        except:
            return {"message": ERROR_INSERTING}, 500

        return item.json(), 201

    @classmethod
    @jwt_required
    def delete(cls, name: str):
        item = ItemModel.find_by_name(name)
        if item:
            item.delete_from_db()
            return {"message": ITEM_DELETED}
        return {"message": ITEM_NOT_FOUND}

    @classmethod
    @jwt_required
    def put(cls, name: str):
        data = Item.parser.parse_args()

        item = ItemModel.find_by_name(name)

        if item is None:
            item = ItemModel(name, **data)
        else:
            item.price = data["price"]

        item.save_to_db()

        return item.json()


class ItemList(Resource):
    @classmethod
    def get(cls):
        return {"items": [item.json() for item in ItemModel.find_all()]}, 200


# ADMIN-ONLY VERSION OF DELETE ENDPOINT (IMPORT get_jwt_claims AT TOP):
#     @jwt_required
#     def delete(self, name):
#         claims = get_jwt_claims()
#         if not claims['is_admin']:
#             return {'message': 'Admin privilege required'}, 401
#         item = ItemModel.find_by_name(name)
#         if item:
#             item.delete_from_db()
#
#         return {'message': 'Item deleted'}

# JWT-OPTIONAL VERSION OF ITEMS ENDPOINT (IMPORT jwt_optional, get_jwt_identity AT TOP):
#
# class ItemList(Resource):
#     @jwt_optional
#     def get(self):
#         user_id = get_jwt_identity()
#         items = [item.json() for item in ItemModel.find_all()]
#         if user_id:
#             return {'items': items}, 200
#         return {
#             'items': [item['name'] for item in items],
#             'message': 'More data available if you log in.'
#         }, 200
