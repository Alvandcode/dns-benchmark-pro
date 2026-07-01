def recommend(results):

    best = max(results, key=lambda x: x["score"])

    return {
        "recommended": best["ip"],
        "score": best["score"]
    }
