import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas
import numpy as np
import datetime

matplotlib.style.use('ggplot')
matplotlib.rcParams['figure.figsize'] = 17, 5

scan_data = []
with open("scan-stats.json", "r") as f:
    lines = f.readlines()
    for l in lines:
        scan_data.append(eval(l))

df = pandas.DataFrame(scan_data)
df['Started'] = pandas.to_datetime(df['Started']).astype(datetime.datetime)
df['Finished'] = pandas.to_datetime(df['Finished']).astype(datetime.datetime)
df['Scan took'] = df['Finished'] - df['Started']
df['Scan took'] = (df['Scan took'] / np.timedelta64(1, 'h')).astype(float)
df = df.set_index('Started')
df = df.sort_index()
df = df.fillna(0)
df['NamesCertUsed'] = (df['ProcessedNames'] - df['NamesCertNotUsed'])

for c in df:
    if c.startswith("Names"):
        df[c] = (df[c]/df['ProcessedNames'])*100.0
    if c.startswith("Certs"):
        df[c] = (df[c]/df['ProcessedCerts'])*100.0

df['HostProblemSum'] = df['NamesDontExist'] + df['NamesUnavailable'] + df['NamesSkipped']
df['TLSProblemSum'] = df['NamesTLSError'] + df['NamesUsingIncompleteChain'] + df['NamesUsingExpiredCert'] + df['NamesUsingWrongCert'] + df['NamesUsingSelfSignedCert'] + df['NamesUsingMiscInvalidCert']

# first plot, adoption info
fig, axes = plt.subplots()
axes.plot(df.index, df['NamesCertUsed'], label='Names using their certificate')
axes.plot(df.index, df['CertsTotallyUsed'], label='Completely used certificates')
axes.plot(df.index, df['CertsPartiallyUsed'], label='Partially used certificates')
axes.plot(df.index, df['CertsUnused'], label='Unused certificates')
lgd = axes.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0., ncol=4)

# second plot, scan info
fig2, axes2 = plt.subplots()
l1 = axes2.plot(df.index, df['ProcessedCerts'], label='Certificates')
l2 = axes2.plot(df.index, df['ProcessedNames'], label='DNS names')
tickLabels = axes2.get_xticklabels()
ax2 = axes2.twinx()
ax2.set_ylabel('Hours')
l3 = ax2.plot(df.index, df['Scan took'], label='Scan duration', linestyle='--', color='black')

ls = l1+l2+l3
labs = [l.get_label() for l in ls]
lgd2 = ax2.legend(ls, labs, bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0., ncol=3)

# third plot, name problems
fig3, axes3 = plt.subplots()
axes3.plot(df.index, df['NamesDontExist'], label='Invalid DNS')
axes3.plot(df.index, df['NamesUnavailable'], label='Refused/Unavailable')
axes3.plot(df.index, df['NamesSkipped'], label='Timed out')
axes3.plot(df.index, df['NamesTLSError'], label='TLS error')
axes3.plot(df.index, df['NamesUsingIncompleteChain'], label='Sent incomplete chain')
axes3.plot(df.index, df['NamesUsingExpiredCert'], label='Using expired cert')
axes3.plot(df.index, df['NamesUsingWrongCert'], label='Using wrong cert')
axes3.plot(df.index, df['NamesUsingSelfSignedCert'], label='Using self signed cert')
axes3.plot(df.index, df['NamesUsingMiscInvalidCert'], label='Using misc. invalid cert')
axes3.plot(df.index, df['HostProblemSum'], label='Host problems sum', color='black', linestyle='--')
axes3.plot(df.index, df['TLSProblemSum'], label='TLS problems sum', color='red', linestyle='--')
lgd3 = axes3.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0., ncol=4)

# fourth plot, cipher suite info
fig4, axes4 = plt.subplots()
cipherStuff = []
for i, v in df.iterrows():
    v['CipherHist']['index'] = i
    cipherStuff.append(v['CipherHist'])
vf = pandas.DataFrame(cipherStuff)
vf = vf.set_index('index')
vf = vf.sort_index()
vf['sum'] = vf.sum(axis=1)
for c in vf:
    if c != "sum":
        vf[c] = (vf[c] / vf['sum']) * 100.0
vf = vf.fillna(0)
vf['sum'] = None
vf.plot(ax=axes4)
lgd4 = axes4.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0., ncol=3)
# axes4.set_yscale('log')

# fifth plot, feature usage
fig5, axes5 = plt.subplots()
axes5.plot(df.index, df['NamesServingSCTs'], label="Names serving SCTs")
axes5.plot(df.index, df['NamesWithOCSPStapled'], label="Names serving stapled OCSP")
lgd5 = axes5.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0., ncol=3)

for ax in [axes, axes2, axes3, axes4, axes5]:
    matplotlib.pyplot.sca(ax)
    plt.xticks(rotation=30, ha='right', visible=True)
    # ax.set_xlim(df.index.min(), df.index.max())
    ax.set_xlabel("")
    # ax.grid(False)
# ax2.set_xlim(df.index.min(), df.index.max())
ax2.set_xlabel("")
ax2.grid(False)
from matplotlib.ticker import FormatStrFormatter
for ax in [axes, axes3, axes4, axes5]:
    ax.yaxis.set_major_formatter(FormatStrFormatter("%s %%"))

fig.savefig("adoption.png", bbox_extra_artists=(lgd,), bbox_inches='tight')
fig2.savefig("scan-info.png", bbox_extra_artists=(lgd2,), bbox_inches='tight')
fig3.savefig("problems.png", bbox_extra_artists=(lgd3,), bbox_inches='tight')
fig4.savefig("ciphers.png", bbox_extra_artists=(lgd4,), bbox_inches='tight')
fig5.savefig("features.png", bbox_extra_artists=(lgd5,), bbox_inches='tight')

