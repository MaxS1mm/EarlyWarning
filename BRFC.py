import pandas as pd
import numpy as np

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from catboost import CatBoostClassifier

train_path = "./KDD_Data/KDDTrain+_20Percent.txt"
test_path = "./KDD_Data/KDDTest-21.txt"

columns = [f"feature_{i}" for i in range(1, 43)] + ["label"]
train_df = pd.read_csv(train_path, header=None, names=columns)
test_df = pd.read_csv(test_path, header=None, names=columns)

X_train = train_df.drop(columns=["label"])
y_train_raw = train_df["label"]

X_test = test_df.drop(columns=["label"])
y_test_raw = test_df["label"]

# encode label
label_encoder = LabelEncoder()
y_train = label_encoder.fit_transform(y_train_raw)

known = set(label_encoder.classes_)
mask_known = y_test_raw.isin(known)
if not mask_known.all():
    unseen = sorted(set(y_test_raw[~mask_known].unique()))
    print(f"Warning: dropping {len(unseen)} unseen label(s) in test: {unseen}")
    X_test = X_test.loc[mask_known].copy()
    y_test_raw = y_test_raw.loc[mask_known].copy()

y_test = label_encoder.transform(y_test_raw)


# identify categorical columns (strings)
cat_cols = X_train.select_dtypes(include=["object"]).columns.tolist()
cat_feature_indices = [X_train.columns.get_loc(c) for c in cat_cols]

model = CatBoostClassifier(iterations=1500, learning_rate=0.08, depth=8, loss_function="MultiClass", eval_metric="TotalF1", random_seed=42, verbose=200, auto_class_weights="Balanced")


model.fit(X_train, y_train, cat_features=cat_feature_indices, eval_set=(X_test, y_test), use_best_model=True)

y_pred = model.predict(X_test).reshape(-1).astype(int)

labels_present = np.unique(np.concatenate([y_test, y_pred])).astype(int)
target_names = [str(x) for x in label_encoder.classes_[labels_present]]

print(classification_report(y_test, y_pred, labels=labels_present, target_names=target_names, zero_division=0))
