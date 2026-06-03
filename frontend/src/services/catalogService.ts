export interface CatalogChapter {
  id: string;
  title: string;
  type: 'pdf' | 'html';
  url: string;
}

export interface CatalogBook {
  id: string;
  title: string;
  description?: string;
  chapters: CatalogChapter[];
  classId: string;
  subjectId: string;
}

export interface CatalogSubject {
  id: string;
  name: string;
  books: CatalogBook[];
}

export interface CatalogClass {
  id: string;
  name: string;
  subjects: CatalogSubject[];
}

interface CatalogResponse {
  classes: CatalogClass[];
}

const CATALOG_CACHE_KEY = 'ncert:catalog:v1';
const CATALOG_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const CATALOG_URL = process.env.REACT_APP_NCERT_CATALOG_URL || 'https://shaheryar3.github.io/ncert-books/catalog.json';

const defaultCatalog: CatalogResponse = {
  classes: [
    {
      id: 'class-10',
      name: 'Class 10',
      subjects: [
        {
          id: 'science',
          name: 'Science',
          books: [
            {
              id: 'science-10',
              classId: 'class-10',
              subjectId: 'science',
              title: 'NCERT Science',
              description: 'Set REACT_APP_NCERT_CATALOG_URL to your GitHub-hosted catalog JSON.',
              chapters: [
                {
                  id: 'sample-chapter-1',
                  title: 'Sample Chapter',
                  type: 'pdf',
                  url: 'https://ncert.nic.in/textbook/pdf/jesc101.pdf'
                }
              ]
            }
          ]
        }
      ]
    }
  ]
};

const normalizeCatalog = (catalog: CatalogResponse): CatalogResponse => {
  return {
    classes: catalog.classes.map((classItem) => ({
      ...classItem,
      subjects: classItem.subjects.map((subject) => ({
        ...subject,
        books: subject.books.map((book) => ({
          ...book,
          classId: book.classId || classItem.id,
          subjectId: book.subjectId || subject.id,
        }))
      }))
    }))
  };
};

const getCachedCatalog = (): CatalogResponse | null => {
  try {
    const cached = localStorage.getItem(CATALOG_CACHE_KEY);
    if (!cached) return null;
    const parsed = JSON.parse(cached) as { storedAt: number; data: CatalogResponse };
    if (Date.now() - parsed.storedAt > CATALOG_CACHE_TTL_MS) return null;
    return parsed.data;
  } catch {
    return null;
  }
};

const saveCatalogCache = (data: CatalogResponse): void => {
  localStorage.setItem(CATALOG_CACHE_KEY, JSON.stringify({ storedAt: Date.now(), data }));
};

class CatalogService {
  async getCatalog(): Promise<CatalogResponse> {
    const cached = getCachedCatalog();
    if (cached) return normalizeCatalog(cached);

    try {
      const response = await fetch(CATALOG_URL, { cache: 'no-store' });
      if (!response.ok) throw new Error('Failed to fetch catalog');
      const payload = await response.json() as CatalogResponse;
      const normalized = normalizeCatalog(payload);
      saveCatalogCache(normalized);
      return normalized;
    } catch {
      return normalizeCatalog(defaultCatalog);
    }
  }
}

export const catalogService = new CatalogService();
