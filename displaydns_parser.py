import os

DISPLAYDNS_LOG = 'display_dns_log.txt'


def get_parsed_dns_table():
    """
       Retrieves the DNS table using the "ipconfig /displaydns" command and parses it into a dictionary.

       :return: Dictionary containing the parsed DNS table
       """
    # Retrieve the output of the "ipconfig /displaydns" command
    display_dns = os.popen("ipconfig /displaydns").read()
    dns_title_data_split = [i.split("----------------------------------------") for i in display_dns.split("\n\n")[1:]]

    dns_title_data_dict = {}

    title = ""
    for i in dns_title_data_split:
        if len(i) > 1:
            dns_title_data_dict[i[0].strip()] = i[1].strip()
            title = i[0].strip()
        else:
            dns_title_data_dict[title] += "\n" + i[0].strip()

    final_dns_table = {}

    # print(dns_title_data_dict)
    # Parse the raw DNS table data into a nested dictionary structure
    for i, j in dns_title_data_dict.items():
        if i.strip() not in final_dns_table:
            final_dns_table[i.strip()] = {}  # j.split("\n")
        for k in j.split("\n"):
            try:
                if k.split(":")[0].strip().strip(" .") not in final_dns_table[i]:
                    final_dns_table[i][k.split(":")[0].strip().strip(" .")] = []

                if k.split(":")[0].strip().strip(" .") != 'AAAA Record':
                    final_dns_table[i][k.split(":")[0].strip().strip(" .")].append(k.split(":")[1].strip())

                # == 'AAAA Record'
                else:
                    final_dns_table[i][k.split(":")[0].strip().strip(" .")].append(
                        ':'.join([i.strip() for i in k.split(":")[1:]]))
            except IndexError as e:
                final_dns_table[i][k] = ''
                # print(e)
                # print(k)
                pass

        # del final_dns_table[i]['']

    # print(final_dns_table)

    for i, j in final_dns_table.items():
        # print(i, j)
        pass

    # print('----------------------------------------')

    return final_dns_table


def get_site_ip_from_dns_table(site, dns_table):
    """
        Retrieves the IP addresses associated with a given site from the parsed DNS table.

        :param site: The site to retrieve IP addresses for
        :param dns_table: The parsed DNS table
        :return: List of IP addresses associated with the given site
        """
    # dns_table = get_parsed_dns_table()

    if site in dns_table:
        return (dns_table[site]['A (Host) Record'] if 'A (Host) Record' in dns_table[site] else []) + (
            dns_table[site]['AAAA Record'] if 'AAAA Record' in dns_table[site] else [])
    else:
        return []


if __name__ == '__main__':
    dns_table = get_parsed_dns_table()
    # print(dns_table)
    print(get_site_ip_from_dns_table("google.com", dns_table))
