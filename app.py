#Implementing ASCON128 Authenticated Encryption

import numpy as np
import streamlit as st
from streamlit_toggle import st_toggle_switch
from streamlit_extras.add_vertical_space import add_vertical_space

def bin_to_hex(n):
    num = int(n,2)
    hex_num = format(num,'x')
    return hex_num


def num_to_bin_list(k):
    return list(map(int,bin(k)[2:].zfill(8)))

def create_IV(k = 128,r = 64,a = 12,b = 6):
    iv = []
    iv.extend(num_to_bin_list(k))
    iv.extend(num_to_bin_list(r))
    iv.extend(num_to_bin_list(a))
    iv.extend(num_to_bin_list(b))
    iv.extend([0]*(160-k))    
    return iv


def initial_input(K,N):
    S = []
    iv = create_IV()
    S.extend(iv)
    S.extend(K)
    S.extend(N)
    return S

def Liner_Diffusion_Layer(S,i,Linear_diffusion_layer):
    S = S[i*64:(i+1)*64]

    x1 = np.roll(S,Linear_diffusion_layer[i][1])
    x2 = np.roll(S,Linear_diffusion_layer[i][2])

    x = xor_2_lists(S, xor_2_lists(x1, x2))

    return x
    
def xor_2_lists(x,y):
    return list(a^b for a,b in zip(x,y))

def trailing_zeros(K,n):
    return K + [0] * (n-len(K))

def leading_zeros(K,n):
    return [0] * (n-len(K)) + K

def initialization(K, N):
    S = initial_input(K, N)
    S = Permutation(K, S, a_or_b = 'a')
    S[64:] = xor_2_lists(S[64:], leading_zeros(K, 256)) 
    return S

def to_hex(l):
    
    ans = ''
    for i in range(len(l)):
        ans+= hex_dict[l[i]] 
        
    return list(map(int,ans))


def Permutation(K, S, a_or_b):
    aod_p12 = ['f0','e1','d2','c3','b4','a5','96','87','78','69','5a','4b']
    #aod_p8 = ['b4','a5','96','87','78','69','5a','4b']
    aod_p6 = ['96','87','78','69','5a','4b']

    
    substitution_layer = {'0':'4','1':'b','2':'1f','3':'14','4':'1a','5':'15','6':'9','7':'2','8':'1b','9':'5','a':'8','b':'12','c':'1d','d':'3','e':'6','f':'1c','10':'1e','11':'13','12':'7','13':'e','14':'0','15':'d','16':'11','17':'18','18':'10','19':'c','1a':'1','1b':'19','1c':'16','1d':'a','1e':'f','1f':'17'}

    Linear_diffusion_layer = [[None,19,28],[None,61,39],[None, 1,6],[None, 10,17],[None,7,41]]
    
    #Addition of Constants
    
    if a_or_b =='a':
        iteration = 12
        aod = aod_p12
    
    elif a_or_b == 'b':
        iteration = 6
        aod = aod_p6
    
    for j in range(iteration):
        
        #Addition of Constants
        l2 = to_hex(aod[j])
        S[128:192] = xor_2_lists(S[128:192],[0] * (64 - len(l2)) + l2)
        

        # Substitution Layer
        for i in range(64):
            bin_no = bin_to_hex(str(S[i] * 10000 + S[i+64] * 1000 + S[i+128] * 100 + S[i+192] * 10 + S[i+256]))
            output = substitution_layer[bin_no]
            output = list(map(int,bin(int(output,16))[2:].zfill(5)))
            
            S[i], S[i+64], S[i+128], S[i+192], S[i+256] = output
            
            
        #Linear Diffusion Layer
        final_S = []
        for i in range(5):
            final_S.extend(Liner_Diffusion_Layer(S,i,Linear_diffusion_layer))
            
        
        S = final_S
    return S


def associated_data(S, A_data, K, final = 0):
    S[:64] = xor_2_lists(S[:64], A_data)
    
    S = Permutation(K, S, a_or_b = 'b')
    
    if final:
        S[-1] = S[-1] ^ 1   
        
    return S


def finalization(K, S):
    
    
    S[64:] = xor_2_lists(S[64:], trailing_zeros(K, 256))
    
    S = Permutation(K, S, a_or_b = 'a')
    
    Token = xor_2_lists(S[192:], K)
    
    print("The token produced here in this encryption is as follows: ")
    print(bin_list_to_hex(Token))
    
    return Token

def bin_list_to_hex(l):
    ans = ''
    for i in range(0,len(l),4):
        num = str(l[i]*1000 + l[i+1] * 100 + l[i+2] * 10 + l[i+3])
        ans += format(int(num,2),'x')
    return ans
        

def str_to_bin(plain_text):
    bin_list = []
    
    for char in plain_text:
        bin_list.append(bin(ord(char))[2:].zfill(8))
        
    return bin_list


# x0 = S[:64]
# x1 = S[64:128]
# x2 = S[128:192]
# x3 = S[192:256]
# x4 = S[256:320]


global hex_dict
hex_dict = {'0' : '0000','1' : '0001','2':'0010','3':'0011','4':'0100','5':'0101','6':'0110','7':'0111','8':'1000','9':'1001','a':'1010','A':'1010','b':'1011','B':'1011','c':'1100','C':'1100','d':'1101','D':'1101','e':'1110','E':'1110','f':'1111','F':'1111'}

if __name__ == "__main__":
    st.set_page_config(page_title="ASCON Implementation", layout="wide")
    a,b,c = st.columns(3)
    with b:
        st.markdown("<h1 style='text-align: center; color: Dark Gray;'>ASCON Cipher</h1>",
            unsafe_allow_html=True)

    ques = st_toggle_switch(
        label="Encryption/Decryption ",
        key="ED",
        default_value=False,
        label_after='Decryption',
        inactive_color="#D3D3D3",  # optional
        active_color="#11567f",  # optional
        track_color="#29B5E8",  # optional
    )

    col1, col2 = st.columns(2)
    with col1:
        K_hex = st.text_input("Enter the Key (in hex): ")
        N_hex = st.text_input("Enter the Nonce (in hex): ")
        AT = st.text_input("Enter the Associated data (in hex): ")
        if ques == False:
            PT = st.text_input("Enter the Plain Text (in hex): ")
        else:
            CT = st.text_input("Enter the Cipher Text (in hex): ")

        col11, col12, col13 = st.columns(3)
        with col12:
            submit = st.button("Submit")

    if submit:
        K = to_hex(K_hex)
        N = to_hex(N_hex)
        AT = to_hex(AT)

        S = initialization(K, N)

        if len(AT)%64 != 0:
            AT = leading_zeros(AT, ((len(AT)//64) + 1) * 64)

        i = 0
        while(i < ((len(AT)//64) - 1)):
            S = associated_data(S, AT[i*64:(i+1)*64], K)
            i += 1
        
        S = associated_data(S, AT[i*64:(i+1)*64], K, final=1)

        if ques == False:
            PT = to_hex(PT)
            if len(PT)%64 != 0:
                PT = leading_zeros(PT, ((len(PT)//64) + 1) * 64)
            
            CT = ''
            i = 0
            while(i < ((len(PT)//64) - 1)):
                S[:64] = xor_2_lists(S[:64],PT[i*64, (i+1)*64])
                CT += bin_list_to_hex(S[:64])
                S = Permutation(K, S, a_or_b = 'b')
                i += 1

            S[:64] = xor_2_lists(S[:64],PT[i*64: (i+1)*64])
            
            CT += bin_list_to_hex(S[:64])
            print("The Cipher Text created in the process is as follows: ")
            print(CT)

            Token = finalization(K, S)
            with col2:
                add_vertical_space(7)
                st.text("The Cipher Text Created is:")
                st.text(CT)
                st.text("The Token Created is:")
                st.text(bin_list_to_hex(Token))


        elif ques == True:
            CT = to_hex(CT)
            if len(CT)%64 != 0:
                CT = leading_zeros(CT, ((len(CT)//64) + 1) * 64)
            
            PT = ''
            i = 0
            while(i < ((len(CT)//64) - 1)):
                S[:64] = xor_2_lists(S[:64],CT[i*64, (i+1)*64])
                PT += bin_list_to_hex(S[:64])
                S = Permutation(K, S, a_or_b = 'b')
                i += 1

            S[:64] = xor_2_lists(S[:64],CT[i*64: (i+1)*64])
            
            PT += bin_list_to_hex(S[:64])
            print("The Plain Text created in the process is as follows: ")
            print(PT)
            Token = finalization(K, S)

            with col2:
                add_vertical_space(7)
                st.text("The Plain Text Created is:")
                st.text(PT)
                st.text("The Token Created is:")
                st.text(bin_list_to_hex(Token))

