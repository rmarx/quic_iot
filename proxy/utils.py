from copy import deepcopy
import numpy as np

LOCAL_DNS = {}
MAX_INTERVAL_ERROR = 1.0
MAX_INTERVAL_ERROR_RATIO = 0.1 # unused
MAX_REGULAR_INTERVAL = 7200+60
MAX_PKTLEN_ERROR = 0.05
PROCESSING_INTERVAL_LONG = 5
PROCESSING_INTERVAL_SHORT = 1
SHORT_PKT_THRES = 5


def get_lcs(S1, S2):
    m = len(S1)
    n = len(S2)
    L = [[0 for x in range(n+1)] for x in range(m+1)]

    # Building the mtrix in bottom-up way
    for i in range(m+1):
        for j in range(n+1):
            if i == 0 or j == 0:
                L[i][j] = 0
            elif S1[i-1] == S2[j-1]:
                L[i][j] = L[i-1][j-1] + 1
            else:
                L[i][j] = max(L[i-1][j], L[i][j-1])

    index = L[m][n]
    # print(m, n, index, np.array(L))

    lcs_ret = [None] * index #(index+1)
    # print(lcs_ret)
    # lcs_ret[index] = None

    i = m
    j = n
    while i > 0 and j > 0:
        
        # print(S1[i-1] == S2[j-1], S1[i-1].to_string(), S2[j-1].to_string())
        if S1[i-1] == S2[j-1]:
            lcs_ret[index-1] = S2[j-1] # deepcopy(S1[i-1])
            i -= 1
            j -= 1
            index -= 1

        elif L[i-1][j] > L[i][j-1]:
            i -= 1
        else:
            j -= 1
            
    # Printing the sub sequences
    # print('lcs_ret', lcs_ret)
    return lcs_ret

if __name__ == "__main__":
    # S1 = "AACVADDAB"
    # S2 = "CBDDACABSDA"
    # S1 = "ZZZ"
    # S2 = "ZZZ"
    S1 = [[1, '142.250.31.0/8', 0, 0, 427], [1, '142.250.31.0/8', 0, 0, 493], [1, "www.google.com.'", 1, 0, 1392], [1, "www.google.com.'", 1, 0, 93], [1, "www.google.com.'", 1, 0, 67], [1, "www.google.com.'", 1, 0, 409], [1, "www.google.com.'", 1, 0, 87], [1, "www.google.com.'", 1, 0, 565], [1, "www.google.com.'", 1, 0, 73], [1, "www.google.com.'", 1, 0, 302], [1, "www.google.com.'", 1, 0, 173], [1, "www.google.com.'", 1, 0, 263], [1, "www.google.com.'", 1, 0, 122], [1, "youtube-ui.l.google.com.'", 1, 0, 1392], [1, "play.googleapis.com.'", 1, 0, 603], [1, "play.googleapis.com.'", 1, 0, 204], [1, "play.googleapis.com.'", 1, 0, 171], [1, "fcm.googleapis.com.'", 1, 0, 558]]
    S2 = [[1, "youtube-ui.l.google.com.'", 1, 0, 1392], [1, '142.250.31.0/8', 0, 0, 427], [1, "www.google.com.'", 1, 0, 1392], [1, "clients.l.google.com.'", 1, 0, 278], [1, "www.google.com.'", 1, 0, 458], [1, "clients.l.google.com.'", 1, 0, 337], [1, "clients.l.google.com.'", 1, 0, 303], [1, "fcm.googleapis.com.'", 1, 0, 398]]

    lcs_ret = get_lcs(S1, S2)
    print("S1 :", S1)
    print("S2 :", S2)
    print("LCS:", lcs_ret)