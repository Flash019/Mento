# model/enums.py
import enum

class OrderStatus(str, enum.Enum):
    pending = "pending"
    accepted = "accepted"
    preparing = "preparing"
    ready_for_pickup = "ready_for_pickup"
    out_for_delivery = "out_for_delivery"
    delivered = "delivered"
    cancelled = "cancelled"
    failed = "failed"

class DeliveryAssignmentStatus(str, enum.Enum):
    assigned = "assigned"
    accepted = "accepted"
    picked = "picked"
    completed = "completed"
    cancelled = "cancelled"

class PaymentMethod(str, enum.Enum):
    card = "card"
    upi = "upi"
    wallet = "wallet"
    cash = "cash"
    netbanking = "netbanking"
    third_party = "third_party"

class PaymentStatus(str, enum.Enum):
    pending = "pending"
    paid = "paid"
    failed = "failed"
    refunded = "refunded"
    cancelled = "cancelled"
