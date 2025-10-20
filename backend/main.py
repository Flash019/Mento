from fastapi import FastAPI
from sql_db import Base, engine
from fastapi.middleware.cors import CORSMiddleware
# Import all models here so SQLAlchemy knows about them
from model.user import User
from model.restaurant import Restaurant, RestaurantLocation
from model.order import Order
from model.menu_item import MenuItem
from model.order_item import OrderItem
from model.payment import Payment
from model.review import Review
from model.delivery_person import DeliveryPerson

# Import your routers
from router import upload, auth_user,auth_restro,auth_delivery_person,menu_add_restro,near_by_restaurant_search

# Create tables after all models are imported
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Include routers
app.include_router(upload.router, tags = ['Upload Image'])
app.include_router(auth_user.router, tags=['User'])
app.include_router(auth_restro.router,tags=["Restaurant"])
app.include_router(auth_delivery_person.router, tags=['Rider'])
app.include_router(menu_add_restro.router,tags=['Menu Create'])
app.include_router(near_by_restaurant_search.router, tags=['NearByRestaurannt'])