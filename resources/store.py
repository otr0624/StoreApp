from flask_restful import Resource, reqparse
from models.store import StoreModel

STORE_DELETED = "Store deleted."
STORE_NOT_FOUND = "Store not found."
STORE_ALREADY_EXISTS = "A store with name {} already exists."
ERROR_CREATING = "An error occurred creating the store."


class Store(Resource):
    @classmethod
    def get(cls, name: str):
        store = StoreModel.find_by_name(name)
        if store:
            return store.json()
        return {"message": STORE_NOT_FOUND}, 404

    @classmethod
    def post(cls, name: str):
        if StoreModel.find_by_name(name):
            return (
                {"message": STORE_ALREADY_EXISTS.format(name)},
                400,
            )

        store = StoreModel(name)
        try:
            store.save_to_db()
        except:
            return {"message": ERROR_CREATING}, 500

        return store.json(), 201

    @classmethod
    def delete(cls, name: str):
        store = StoreModel.find_by_name(name)
        if store:
            store.delete_from_db()

        return {"message": STORE_DELETED}


class StoreList(Resource):
    @classmethod
    def get(cls):
        return {"stores": [store.json() for store in StoreModel.find_all()]}
