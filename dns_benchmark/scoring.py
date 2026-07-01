class DNSScore:

    def __init__(self, stats):
        self.stats = stats

    def calculate(self):

        score = 100

        score -= self.stats.packet_loss * 0.6
        score -= min(self.stats.average / 4, 25)

        return max(round(score, 2), 0)


def grade(score):
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    return "C"
