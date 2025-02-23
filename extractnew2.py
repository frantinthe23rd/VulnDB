import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re

# Connect to SQLite Database
def connect_db(db_path="vulnerabilities.db"):
    conn = sqlite3.connect(db_path)
    return conn

# Extract Data for CSV and Heatmap
def extract_data(conn):
    query = '''
        SELECT c.group_id AS publisher,
               c.artifact_id AS product,
               c.version AS version,
               v.cve,
               v.cvss_score,
               v.severity,
               v.published_date
        FROM components c
        JOIN vulnerabilities v ON c.component_id = v.component_id
    '''
    df = pd.read_sql_query(query, conn)

    # Extract Year Detected
    def extract_year(row):
        if pd.notnull(row['published_date']) and row['published_date'] != 'n/a':
            return row['published_date'][:4]
        elif pd.notnull(row['cve']) and re.search(r'CVE-(\d{4})', row['cve']):
            return re.search(r'CVE-(\d{4})', row['cve']).group(1)
        else:
            return 'Unknown'

    df['year_detected'] = df.apply(extract_year, axis=1)

    # Add Severity Columns
    df['critical'] = df.apply(lambda x: x['cve'] if x['cvss_score'] >= 9 else None, axis=1)
    df['high'] = df.apply(lambda x: x['cve'] if 7 <= x['cvss_score'] < 9 else None, axis=1)
    df['medium'] = df.apply(lambda x: x['cve'] if 4 <= x['cvss_score'] < 7 else None, axis=1)
    df['low'] = df.apply(lambda x: x['cve'] if 0 < x['cvss_score'] < 4 else None, axis=1)

    return df

# Generate Detailed CSV
def generate_detailed_csv(df, filename="vulnerability_detailed.csv"):
    df.to_csv(filename, index=False)
    print(f"✅ Detailed CSV file saved as {filename}")

# Generate Summary CSV with Fixes
def generate_summary_csv(df, filename="vulnerability_summary.csv"):
    summary_df = df.groupby(['publisher', 'product', 'year_detected']).agg(
        num_vulnerable_versions=('version', pd.Series.nunique),
        critical=('critical', pd.Series.nunique),
        high=('high', pd.Series.nunique),
        medium=('medium', pd.Series.nunique),
        low=('low', pd.Series.nunique),
        total_vulnerabilities=('cve', pd.Series.nunique)
    ).reset_index()
    summary_df.to_csv(filename, index=False)
    print(f"✅ Summary CSV file saved as {filename}")

# Generate Heatmap for Top 10 Products
def generate_heatmap(df):
    if df.empty:
        print("⚠ No data available for heatmap generation.")
        return

    # Count total vulnerabilities per product
    product_counts = df.groupby('product').cve.nunique().reset_index(name='total_vulnerabilities')
    top_products = product_counts.nlargest(10, 'total_vulnerabilities')['product']

    # Filter data for top 10 products
    top_df = df[df['product'].isin(top_products)]

    # Pivot table for heatmap
    pivot_df = top_df.pivot_table(
        index='product',
        columns='year_detected',
        values='cve',
        aggfunc=pd.Series.nunique,
        fill_value=0
    )

    # Plot heatmap
    plt.figure(figsize=(14, 8))
    sns.heatmap(pivot_df, annot=True, fmt="d", cmap="YlOrRd", linewidths=0.5)
    plt.title("Top 10 OSS Java Components - Vulnerability Heatmap")
    plt.xlabel("Year Detected")
    plt.ylabel("Product")
    plt.tight_layout()

    heatmap_filename = "vulnerability_heatmap.png"
    plt.savefig(heatmap_filename)
    plt.show()
    print(f"✅ Heatmap saved as {heatmap_filename}")

# Main Function
def main():
    conn = connect_db()
    df = extract_data(conn)
    generate_detailed_csv(df)
    generate_summary_csv(df)
    generate_heatmap(df)
    conn.close()

if __name__ == "__main__":
    main()

