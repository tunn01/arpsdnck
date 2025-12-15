import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

# Đọc dữ liệu
DATA = "arp_dataset.csv"
MODEL_OUT = "arp_mlp.joblib"

try:
    df = pd.read_csv(DATA)
except:
    print("Lỗi: Không tìm thấy file arp_dataset.csv")
    exit()

# Chọn các đặc trưng (Features) để học
features = [
    "opcode","src_ip_oct","dst_ip_oct","src_mac_b","dst_mac_b",
    "is_request","is_reply","is_gratuitous","dst_mac_zero",
    "req_rate_1s","mac_change_count"
]

# Xử lý dữ liệu
X = df[features].fillna(0)
y = (df["label"] == "attack").astype(int)  # Benign=0, Attack=1

# Chia tập train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# Cấu hình mạng Neural Network (MLP)
clf = Pipeline([
    ("scaler", StandardScaler()),
    ("mlp", MLPClassifier(hidden_layer_sizes=(32,16), max_iter=500, random_state=42))
])

print("Đang training mô hình... vui lòng đợi.")
clf.fit(X_train, y_train)

# Đánh giá kết quả
pred = clf.predict(X_test)
print("\nConfusion matrix:")
print(confusion_matrix(y_test, pred))
print("\nReport:")
print(classification_report(y_test, pred, digits=4))

# Lưu mô hình
joblib.dump({"model": clf, "features": features}, MODEL_OUT)
print(f"Đã lưu model thành công tại: {MODEL_OUT}")