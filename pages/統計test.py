import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

st.title("統計")

@st.cache_data
def load_data():
    url = "https://raw.githubusercontent.com/hd3a/kasosuta-dataset/refs/heads/main/scratch_shinya_all.json"
    r = requests.get(url)
    r.raise_for_status()
    return r.json()

data = load_data()

# 平坦化
comments_list = []
for c in data.get("comments", []):
    comments_list.append({
        "id": c["id"],
        "user": c["user"],
        "datetime": c["datetime"],
        "content": c["content"],
        "is_reply": False,
        "parent_id": None
    })
    for r in c.get("replies", []):
        comments_list.append({
            "id": r["id"],
            "user": r["user"],
            "datetime": r["datetime"],
            "content": r["content"],
            "is_reply": True,
            "parent_id": c["id"]
        })

df = pd.DataFrame(comments_list)
df["datetime"] = pd.to_datetime(df["datetime"])

# ------------------------
# 期間指定
# ------------------------
st.subheader("期間指定")
start_date = st.date_input("開始日")
end_date = st.date_input("終了日")

filtered = df.copy()

if start_date and end_date:
    filtered = filtered[
        (filtered["datetime"].dt.date >= start_date) &
        (filtered["datetime"].dt.date <= end_date)
    ]

st.write(f"対象コメント数: {len(filtered)}")

# ------------------------
# ユーザーランキング
# ------------------------
st.subheader("ユーザー投稿数ランキング")

ranking = filtered["user"].value_counts().head(20)
st.dataframe(ranking)

# ------------------------
# 日別コメント推移
# ------------------------
st.subheader("日別コメント数")

daily = filtered.groupby(filtered["datetime"].dt.date).size()

plt.figure()
daily.plot()
plt.xlabel("Date")
plt.ylabel("Comments")
st.pyplot(plt)

# ------------------------
# 返信率
# ------------------------
st.subheader("返信統計")

total = len(filtered)
replies = len(filtered[filtered["is_reply"] == True])
originals = total - replies

st.write(f"元コメント: {originals}")
st.write(f"返信: {replies}")
st.write(f"返信率: {round(replies/total*100,2) if total else 0}%")
