import win32com.client as win32
import xlsxwriter
import tsrreader
from itertools import cycle
from time import sleep
from time import time
from easygui import fileopenbox
import os

start = time()

file = fileopenbox(title="Select SonicWall TSR File",
                   filetypes=".wri", default="*.wri")

dir_path = os.path.dirname(os.path.realpath(__file__))

# Using the pre-existing TSR Reader to process all the data into a Multi-dem Dict
DataInput = tsrreader.TSR_data_format(file)
DataProcess = tsrreader.processors(DataInput.tsr_processing())
DataProcess.cleaner()
# Setting Variable for Data from the Class
data = DataProcess.data

# Creating a xlsx Workbook
book = xlsxwriter.Workbook('output.xlsx')

# Function from creating the Headers and filling in the data from the dictionaries
header_format = book.add_format(
    {'bold': True, 'border': True, 'align': 'center', 'font_size': '12'})

row_format = book.add_format(
    {'bg_color': '#ffffff', 'border': True, 'align': 'center'})


def getheaders(value):
    headers = []

    for k in value.keys():
        try:
            for insidek in value[k].keys():
                headers.append(insidek)
        except:
            headers.append(insidek)

    return(headers)


def fill_data(subject):
    col = 1
    row = 0

    sheetname = book.add_worksheet(subject)
    first_key = list(data[subject].keys())[0]
    sheetname.write(0, 0, "ID", header_format)

    headers = getheaders(data[subject])
    headerCol = {'ID': 0}

    # Creating the headers
    for i in headers:
        if i in headerCol.keys():
            continue
        else:
            headerCol[i] = col
            sheetname.write(row, col, i, header_format)
        col += 1

    # This is setting the Header Row to have the Filter Option
    sheetname.autofilter(0, 0, 0, col)
    # reseting the values for the colmuns and rows
    col = 0
    row = 1

    # Loading in the data
    for i in data[subject].keys():
        col = 0
        # Write to the first Col which is the ID column
        sheetname.write(row, col, i)
        try:
            for x in data[subject][i]:
                sheetname.set_row(row, None, cell_format=row_format)
                sheetname.write(row, headerCol[x], data[subject][i][x])
        except AttributeError:
            sheetname.set_row(row, None, cell_format=row_format)
            sheetname.write(row, headerCol[x], "")
        except TypeError:
            if subject is "Gateway Anti-Virus":
                sheetname.write(row, 1, x)
        row += 1

# This is for filling in data for a single level Dictionary


def flatfill(subject):

    sheetname = book.add_worksheet(subject)
    row = 0
    col = 0

    for k in data[subject].keys():
        sheetname.write(row, col, k, header_format)
        sheetname.write(row, col + 1, data[subject][k], row_format)
        row += 1

# Something is broke in the tsrreader.py for 'Service Groups','Interfaces','NAT Rules','Routes','Capture ATP', 'Anti-Spyware','DPI-SSL','App Control'
# Special 'App Rules', there is another level
# Routes and NAT rules may need 2 seperate sheets per how the TSR reader script works, one for IPv4 and one for IPv6


features = ['Interfaces', 'Address Objects', 'Address Groups',
            'Service Objects', 'Service Groups', 'Zones', 'Access Rules',
            ]

flat_features = ['SystemInfo']

for s in flat_features:
    print(s)
    flatfill(s)

for s in features:
    print(s)
    fill_data(s)

book.close()

# sleep(.5)

excel = win32.gencache.EnsureDispatch('Excel.Application')
wb = excel.Workbooks.Open(
    dir_path + '\output.xlsx')

for f in features:
    ws = wb.Worksheets(f)
    ws.Columns.AutoFit()

for f in flat_features:
    ws = wb.Worksheets(f)
    ws.Columns.AutoFit()

wb.Save()
excel.Application.Quit()

end = time()

print(end - start)
