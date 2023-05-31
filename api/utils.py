import cv2
import numpy as np
import sys
import imageio as iio
from os import remove
from matplotlib import pyplot as plt
from PIL import Image

def get_protected_image(pre_imagen, phone_number):
    alto, ancho, _ = pre_imagen.shape

    tam_recorte = min(alto, ancho)

    inicio_x = (ancho - tam_recorte) // 2
    inicio_y = (alto - tam_recorte) // 2
    fin_x = inicio_x + tam_recorte
    fin_y = inicio_y + tam_recorte

    imagen_recortada = pre_imagen[inicio_y:fin_y, inicio_x:fin_x]

    imgorigy = 1024
    imgorigx = 1024

    yi1 = int(imgorigy)
    xi1 = int(imgorigx)
    dimen = (xi1, yi1)

    imagen = cv2.resize(imagen_recortada, dimen, interpolation=cv2.INTER_LANCZOS4)

    marca = np.zeros((150,150,3),np.uint8)

    def set_number(image,number,column): 
        for y in range(15):
            y += (number*15)
            for x in range(15):
                x += (column*15)
                marca[x,y] = (255,255,255)

    phone_number = [int(x) for x in str(phone_number)]

    for i,number in enumerate(phone_number):
        set_number(marca,number,i)

    marca = np.fliplr(marca)
    marca = np.rot90(marca)

    #################################################################
    if imagen is not None:
        B = 8
        imagen = cv2.cvtColor(imagen, cv2.COLOR_BGR2RGB) 
        b, g, r = cv2.split(imagen)  # Dividir canales
        img1 = b  # Obtener canal azul de la imagen
        h, w = img1.shape  # Se obtiene el valor de las dimensiones
        img1 = img1[:h, :w]
        blocksV = h/B  # Cantidad de bloques de 8x8 en Vertical
        blocksH = w/B  # Cantidad de bloques de 8x8 en Horizontal
        vis0 = np.zeros((h, w), np.float32)  # Matriz hxw con zeros
        Trans = np.zeros((h, w), np.float32)  # Matriz hxw con zeros
        vis0[:h, :w] = img1
        blocksV = int(float(blocksV))  # Convertir el valor flotante a entero
        blocksH = int(float(blocksH))  # Convertir el valor flotante a entero
        ######Se calcula DCT de cada bloque de 8x8 de la imagen#######
        for row in range(blocksV):
            for col in range(blocksH):
                currentblock = cv2.dct(vis0[row*B:(row+1)*B, col*B:(col+1)*B])
                Trans[row*B:(row+1)*B, col*B:(col+1)*B] = currentblock

    ###########################    MARCA DE AGUA   ######################################

    _, dst1 = cv2.threshold(marca, 110, 255, cv2.THRESH_BINARY)
    cv2.imwrite('marcaxd.jpg', dst1)
    datosmarca = iio.v3.imread('marcaxd.jpg')
    datosmarca = cv2.cvtColor(datosmarca, cv2.COLOR_BGR2GRAY)
    datosJ = datosmarca.ravel()
    datosJ5 = int(len(datosJ)/5)
    datosmarca5 = []

    for xmm in range(datosJ5):
        datos55 = datosJ[xmm*5:(xmm+1)*5]
        datosmarca5.append(np.array(datos55))
        datosgM = np.concatenate([datosmarca5])

    cv2.destroyAllWindows()

    ############################################################

    dg2 = np.zeros((h, w), np.float32)
    numaun = 0
    for z in range(blocksV):  # Y
        for zz in range(blocksH):  # X
            dg = Trans[z*B:(z+1)*B, zz*B:(zz+1)*B]
            if len(dg) > 0:
                datosg = dg.ravel()  # convertir matriz a array
                if len(datosg) == 64:
                    datoszigzag2 = [datosg[0], datosg[1], datosg[8], datosg[16], datosg[9], datosg[2], datosg[3], datosg[10], datosg[17], datosg[24], datosg[32], datosg[25], datosg[18], datosg[11], datosg[4], datosg[5], datosg[12], datosg[19], datosg[26], datosg[33], datosg[40], datosg[48], datosg[41], datosg[34], datosg[27], datosg[20], datosg[13], datosg[6], datosg[7], datosg[14], datosg[21], datosg[28],
                                    datosg[35], datosg[42], datosg[49], datosg[56], datosg[57], datosg[50], datosg[43], datosg[36], datosg[29], datosg[22], datosg[15], datosg[23], datosg[30], datosg[37], datosg[44], datosg[51], datosg[58], datosg[59], datosg[52], datosg[45], datosg[38], datosg[31], datosg[39], datosg[46], datosg[53], datosg[60], datosg[61], datosg[54], datosg[47], datosg[55], datosg[62], datosg[63]]
                if datosJ5 > numaun:
                    datosgMD = datosgM[numaun]
                    datoszigzag2 = [datosg[0], datosg[1], datosg[8], datosg[16], datosg[9], datosg[2], datosg[3], datosg[10], datosg[17], datosg[24], datosg[32], datosg[25], datosg[18], datosg[11], datosg[4], datosg[5], datosg[12], datosg[19], datosg[26], datosg[33], datosg[40], datosg[48], datosg[41], datosg[34], datosg[27], datosg[20], datosg[13], datosg[6], datosg[7], datosg[14], datosgMD[0], datosgMD[1],
                                    datosgMD[2], datosgMD[3], datosgMD[4], datosg[56], datosg[57], datosg[50], datosg[43], datosg[36], datosg[29], datosg[22], datosg[15], datosg[23], datosg[30], datosg[37], datosg[44], datosg[51], datosg[58], datosg[59], datosg[52], datosg[45], datosg[38], datosg[31], datosg[39], datosg[46], datosg[53], datosg[60], datosg[61], datosg[54], datosg[47], datosg[55], datosg[62], datosg[63]]
                    matriznueva = [datoszigzag2[0], datoszigzag2[1], datoszigzag2[5], datoszigzag2[6], datoszigzag2[14], datoszigzag2[15], datoszigzag2[27], datoszigzag2[28], datoszigzag2[2], datoszigzag2[4], datoszigzag2[7], datoszigzag2[13], datoszigzag2[16], datoszigzag2[26], datoszigzag2[29], datoszigzag2[42], datoszigzag2[3], datoszigzag2[8], datoszigzag2[12], datoszigzag2[17], datoszigzag2[25], datoszigzag2[30], datoszigzag2[41], datoszigzag2[43], datoszigzag2[9], datoszigzag2[11], datoszigzag2[18], datoszigzag2[24], datoszigzag2[31], datoszigzag2[40], datoszigzag2[44], datoszigzag2[53],
                                datoszigzag2[10], datoszigzag2[19], datoszigzag2[23], datoszigzag2[32], datoszigzag2[39], datoszigzag2[45], datoszigzag2[52], datoszigzag2[54], datoszigzag2[20], datoszigzag2[22], datoszigzag2[33], datoszigzag2[38], datoszigzag2[46], datoszigzag2[51], datoszigzag2[55], datoszigzag2[60], datoszigzag2[21], datoszigzag2[34], datoszigzag2[37], datoszigzag2[47], datoszigzag2[50], datoszigzag2[56], datoszigzag2[59], datoszigzag2[61], datoszigzag2[35], datoszigzag2[36], datoszigzag2[48], datosg[49], datoszigzag2[57], datoszigzag2[58], datoszigzag2[62], datoszigzag2[63]]
                    matriznueva = np.array(matriznueva)
                    matriznueva = matriznueva.reshape(8, 8)
                    dgx = matriznueva
                dg2[z*B:(z+1)*B, zz*B:(zz+1)*B] = dgx
                numaun = numaun+1

    back0 = np.zeros((h, w), np.float32)

    for row in range(blocksV):
        for col in range(blocksH):
            currentblock = cv2.idct(dg2[row*B:(row+1)*B, col*B:(col+1)*B])
            back0[row*B:(row+1)*B, col*B:(col+1)*B] = currentblock

    ##################################################################

    # Crea una imagen RGB a partir del arreglo
    cv2.imwrite('SALIDAB.jpg', back0)

    imgmarca0 = iio.v3.imread('SALIDAB.jpg')

    b2 = imgmarca0

    imgSalidaColor = cv2.merge([r, g, b2])

    cv2.destroyAllWindows()

    remove("SALIDAB.jpg")
    remove("marcaxd.jpg")

    return imgSalidaColor

def get_phone_number(imagen):
    B = 8
    imgorigy = 1024
    imgorigx = 1024

    yi1 = int(imgorigy)
    xi1 = int(imgorigx)
    dimen = (xi1, yi1)
    imagen1 = cv2.resize(imagen, dimen)

    b, g, r = cv2.split(imagen1)


    imgmarca0 = b
    h = imgmarca0.shape[0]
    w = imgmarca0.shape[1]
    blocksV = h/B                   # Cantidad de bloques de 8x8 en Vertical
    blocksH = w/B                   # Cantidad de bloques de 8x8 en Horizontal
    blocksV = int(float(blocksV))   # Se convierte el valor flotante a entero
    blocksH = int(float(blocksH))   # Se convierte el valor flotante a entero
    vis02 = np.zeros((h, w), np.float32)
    DatosPixelEstego = np.zeros((h, w), np.float32)
    vis02[:h, :w] = imgmarca0
    xx2 = 0

    for row2 in range(blocksV):
        for col2 in range(blocksH):
            currentblock2 = cv2.dct(vis02[row2*B:(row2+1)*B, col2*B:(col2+1)*B])
            DatosPixelEstego[row2*B:(row2+1)*B, col2*B:(col2+1)*B] = currentblock2

    marcorigy = 150
    marcorigx = 150

    y1 = int(marcorigy)
    x1 = int(marcorigx)
    datosJ = y1*x1
    datosJ5 = datosJ/5
    datoszzmarca5 = []
    numaunzz = 0

    for zyy in range(blocksV):
        for zzxx in range(blocksH):
            dgzz = DatosPixelEstego[zyy*B:(zyy+1)*B, zzxx*B:(zzxx+1)*B]
            datosgzz = dgzz.ravel()
            if datosJ5 > numaunzz:
                datoszigzagzz = [datosgzz[0], datosgzz[1], datosgzz[8], datosgzz[16], datosgzz[9], datosgzz[2], datosgzz[3], datosgzz[10], datosgzz[17], datosgzz[24], datosgzz[32], datosgzz[25], datosgzz[18], datosgzz[11], datosgzz[4], datosgzz[5], datosgzz[12], datosgzz[19], datosgzz[26], datosgzz[33], datosgzz[40], datosgzz[48], datosgzz[41], datosgzz[34], datosgzz[27], datosgzz[20], datosgzz[13], datosgzz[6], datosgzz[7], datosgzz[14], datosgzz[21], datosgzz[28],
                                datosgzz[35], datosgzz[42], datosgzz[49], datosgzz[56], datosgzz[57], datosgzz[50], datosgzz[43], datosgzz[36], datosgzz[29], datosgzz[22], datosgzz[15], datosgzz[23], datosgzz[30], datosgzz[37], datosgzz[44], datosgzz[51], datosgzz[58], datosgzz[59], datosgzz[52], datosgzz[45], datosgzz[38], datosgzz[31], datosgzz[39], datosgzz[46], datosgzz[53], datosgzz[60], datosgzz[61], datosgzz[54], datosgzz[47], datosgzz[55], datosgzz[62], datosgzz[63]]

                datoszzmarca = [datoszigzagzz[30], datoszigzagzz[31],
                                datoszigzagzz[32], datoszigzagzz[33], datoszigzagzz[34]]
                datoszzmarca5.append(np.array(datoszzmarca))
                numaunzz = numaunzz+1

    datosgMRE = np.concatenate([datoszzmarca5])
    datosgMRE2 = datosgMRE.ravel()
    datosgMRE2 = datosgMRE2.reshape(y1, x1)

    _, dst2 = cv2.threshold(datosgMRE2, 3, 250, cv2.THRESH_BINARY)

    filename_marcarec = "marca_rec.png"
    cv2.imwrite(filename_marcarec, dst2)

    cv2.destroyAllWindows()

    image = Image.open("marca_rec.png")
    image = image.convert('RGB')

    def get_number(column):
        numeros = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]    

        for i in range(10):
            for y in range(15):
                y += (i*15)
                for x in range(15):
                    x += (column*15)
                    r, g, b = image.getpixel((x, y))
                    if (r == 255 and g == 255 and b == 255):
                        numeros[i] += 1

        number = str(numeros.index(max(numeros)))
        return number

    complete_number = ""

    for i in range(10):
        complete_number += get_number(i)
        print(complete_number)

   # remove("marca_rec.png")

    return complete_number

def extract_watermark(filename_imagenentrada):
    imagen = cv2.imread(filename_imagenentrada)

    B = 8
    imgorigy = 1024
    imgorigx = 1024

    yi1 = int(imgorigy)
    xi1 = int(imgorigx)
    dimen = (xi1, yi1)
    imagen1 = cv2.resize(imagen, dimen)

    b, _, _ = cv2.split(imagen1)

    imgmarca0 = b
    h = imgmarca0.shape[0]
    w = imgmarca0.shape[1]
    blocksV = h/B                   # Cantidad de bloques de 8x8 en Vertical
    blocksH = w/B                   # Cantidad de bloques de 8x8 en Horizontal
    blocksV = int(float(blocksV))   # Se convierte el valor flotante a entero
    blocksH = int(float(blocksH))   # Se convierte el valor flotante a entero
    vis02 = np.zeros((h, w), np.float32)
    DatosPixelEstego = np.zeros((h, w), np.float32)
    vis02[:h, :w] = imgmarca0
    xx2 = 0

    for row2 in range(blocksV):
        for col2 in range(blocksH):
            currentblock2 = cv2.dct(vis02[row2*B:(row2+1)*B, col2*B:(col2+1)*B])
            DatosPixelEstego[row2*B:(row2+1)*B, col2*B:(col2+1)*B] = currentblock2

    marcorigy = 150
    marcorigx = 150

    y1 = int(marcorigy)
    x1 = int(marcorigx)
    datosJ = y1*x1
    datosJ5 = datosJ/5
    datoszzmarca5 = []
    numaunzz = 0

    for zyy in range(blocksV):
        for zzxx in range(blocksH):
            dgzz = DatosPixelEstego[zyy*B:(zyy+1)*B, zzxx*B:(zzxx+1)*B]
            datosgzz = dgzz.ravel()
            if datosJ5 > numaunzz:
                datoszigzagzz = [datosgzz[0], datosgzz[1], datosgzz[8], datosgzz[16], datosgzz[9], datosgzz[2], datosgzz[3], datosgzz[10], datosgzz[17], datosgzz[24], datosgzz[32], datosgzz[25], datosgzz[18], datosgzz[11], datosgzz[4], datosgzz[5], datosgzz[12], datosgzz[19], datosgzz[26], datosgzz[33], datosgzz[40], datosgzz[48], datosgzz[41], datosgzz[34], datosgzz[27], datosgzz[20], datosgzz[13], datosgzz[6], datosgzz[7], datosgzz[14], datosgzz[21], datosgzz[28],
                                datosgzz[35], datosgzz[42], datosgzz[49], datosgzz[56], datosgzz[57], datosgzz[50], datosgzz[43], datosgzz[36], datosgzz[29], datosgzz[22], datosgzz[15], datosgzz[23], datosgzz[30], datosgzz[37], datosgzz[44], datosgzz[51], datosgzz[58], datosgzz[59], datosgzz[52], datosgzz[45], datosgzz[38], datosgzz[31], datosgzz[39], datosgzz[46], datosgzz[53], datosgzz[60], datosgzz[61], datosgzz[54], datosgzz[47], datosgzz[55], datosgzz[62], datosgzz[63]]

                datoszzmarca = [datoszigzagzz[30], datoszigzagzz[31],
                                datoszigzagzz[32], datoszigzagzz[33], datoszigzagzz[34]]
                datoszzmarca5.append(np.array(datoszzmarca))
                numaunzz = numaunzz+1

    datosgMRE = np.concatenate([datoszzmarca5])
    datosgMRE2 = datosgMRE.ravel()
    datosgMRE2 = datosgMRE2.reshape(y1, x1)

    _, dst2 = cv2.threshold(datosgMRE2, 3, 250, cv2.THRESH_BINARY)

    filename_marcarec = "marca_rec.png"

    cv2.imwrite(filename_marcarec, dst2)
    cv2.destroyAllWindows()
    #########################################################################################################################

    image = Image.open("marca_rec.png")
    image = image.convert('RGB')

    def get_number(column):
        numeros = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]    

        for i in range(10):
            for y in range(15):
                y += (i*15)
                for x in range(15):
                    x += (column*15)
                    r, g, b = image.getpixel((x, y))
                    if (r > 245 and g  > 245 and b > 245):
                        numeros[i] += 1

        number = str(numeros.index(max(numeros)))
        return number

    complete_number = ""

    for i in range(10):
        complete_number += get_number(i)

    remove("marca_rec.png")

    return(complete_number)

